from __future__ import annotations

import ast
from dataclasses import dataclass, field

from securepy.analysis.helpers import full_name, get_node_line
from securepy.analysis.import_resolver import ImportResolver
from securepy.models.trace import TraceStep
from securepy.scanner.project_index import ProjectIndex
from securepy.scanner.parser import ParsedModule

SOURCE_NAMES = {
    "input",
    "sys.argv",
    "os.environ",
    "os.getenv",
}

REQUEST_PREFIXES = {
    "request.args",
    "request.form",
    "request.json",
    "request.values",
    "request.GET",
    "request.POST",
    "request.body",
}

SINK_NAMES = {
    "eval",
    "exec",
    "compile",
    "os.system",
    "os.popen",
    "open",
    "os.open",
    "pathlib.Path.open",
    "pickle.load",
    "pickle.loads",
}


@dataclass(slots=True)
class TaintInfo:
    tainted: bool
    source_label: str | None = None
    trace: list[TraceStep] = field(default_factory=list)

    @classmethod
    def clean(cls) -> "TaintInfo":
        return cls(tainted=False)

    @classmethod
    def from_source(cls, label: str, file_path: str, line: int) -> "TaintInfo":
        return cls(
            tainted=True,
            source_label=label,
            trace=[TraceStep(kind="source", label=label, file_path=file_path, line=line)],
        )

    def merged(self, other: "TaintInfo") -> "TaintInfo":
        if not self.tainted and not other.tainted:
            return TaintInfo.clean()

        trace: list[TraceStep] = []
        trace.extend(self.trace)
        trace.extend(step for step in other.trace if step not in trace)

        return TaintInfo(
            tainted=True,
            source_label=self.source_label or other.source_label,
            trace=trace,
        )


@dataclass(slots=True)
class SinkHit:
    sink_type: str
    sink_name: str
    file_path: str
    line: int
    arg_tainted: bool
    arg_repr: str | None
    trace: list[TraceStep] = field(default_factory=list)
    detail: dict = field(default_factory=dict)


@dataclass(slots=True)
class ModuleAnalysis:
    module: ParsedModule
    aliases: dict[str, str]
    tainted_names: dict[str, TaintInfo]
    sink_hits: list[SinkHit]
    string_assignments: dict[str, str]
    call_sites: list[dict]


class _FunctionAnalyzer(ast.NodeVisitor):
    def __init__(
        self,
        parent: "ModuleAnalyzer",
        function_name: str | None = None,
        initial_taint: dict[str, TaintInfo] | None = None,
    ) -> None:
        self.parent = parent
        self.function_name = function_name
        self.tainted_names: dict[str, TaintInfo] = initial_taint.copy() if initial_taint else {}
        self.sink_hits: list[SinkHit] = []
        self.string_assignments: dict[str, str] = {}
        self.call_sites: list[dict] = []

    def expr_taint(self, node: ast.AST | None) -> TaintInfo:
        if node is None:
            return TaintInfo.clean()

        if isinstance(node, ast.Name):
            return self.tainted_names.get(node.id, TaintInfo.clean())

        if isinstance(node, ast.Constant):
            return TaintInfo.clean()

        if isinstance(node, ast.Subscript):
            base_name = full_name(node.value)
            if base_name in {"sys.argv", "os.environ"}:
                return TaintInfo.from_source(base_name, str(self.parent.module.path), get_node_line(node))
            return self.expr_taint(node.value)

        if isinstance(node, ast.Attribute):
            name = self.parent.resolve_name(full_name(node))
            if name and any(name.startswith(prefix) for prefix in REQUEST_PREFIXES):
                return TaintInfo.from_source(name, str(self.parent.module.path), get_node_line(node))
            return self.expr_taint(node.value)

        if isinstance(node, ast.Call):
            name = self.parent.resolve_name(full_name(node.func))

            if name in SOURCE_NAMES:
                return TaintInfo.from_source(name, str(self.parent.module.path), get_node_line(node))

            if name:
                summary = self.parent.index.function_summaries.get(name)
                if summary:
                    acc = TaintInfo.clean()
                    for idx, arg in enumerate(node.args):
                        arg_taint = self.expr_taint(arg)
                        if idx in summary.returns_tainted_from_params and arg_taint.tainted:
                            acc = acc.merged(arg_taint)
                    return acc

            acc = TaintInfo.clean()
            for arg in node.args:
                acc = acc.merged(self.expr_taint(arg))
            return acc

        if isinstance(node, ast.BinOp):
            return self.expr_taint(node.left).merged(self.expr_taint(node.right))

        if isinstance(node, ast.JoinedStr):
            acc = TaintInfo.clean()
            for part in node.values:
                acc = acc.merged(self.expr_taint(part))
            return acc

        if isinstance(node, ast.FormattedValue):
            return self.expr_taint(node.value)

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            acc = TaintInfo.clean()
            for elt in node.elts:
                acc = acc.merged(self.expr_taint(elt))
            return acc

        if isinstance(node, ast.Dict):
            acc = TaintInfo.clean()
            for key in node.keys:
                if key is not None:
                    acc = acc.merged(self.expr_taint(key))
            for value in node.values:
                acc = acc.merged(self.expr_taint(value))
            return acc

        return TaintInfo.clean()

    def visit_Assign(self, node: ast.Assign) -> None:
        value_taint = self.expr_taint(node.value)

        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.string_assignments[target.id] = node.value.value

        for target in node.targets:
            if isinstance(target, ast.Name) and value_taint.tainted:
                trace = value_taint.trace + [
                    TraceStep(
                        kind="propagation",
                        label=target.id,
                        file_path=str(self.parent.module.path),
                        line=get_node_line(node),
                    )
                ]
                self.tainted_names[target.id] = TaintInfo(True, value_taint.source_label, trace)

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        value_taint = self.expr_taint(node.value)
        if isinstance(node.target, ast.Name) and value_taint.tainted:
            trace = value_taint.trace + [
                TraceStep(
                    kind="propagation",
                    label=node.target.id,
                    file_path=str(self.parent.module.path),
                    line=get_node_line(node),
                )
            ]
            self.tainted_names[node.target.id] = TaintInfo(True, value_taint.source_label, trace)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = self.parent.resolve_name(full_name(node.func))
        self._record_call_site(node, name)
        if name:
            self._check_sink(node, name)
        self.generic_visit(node)

    def _record_call_site(self, node: ast.Call, name: str | None) -> None:
        self.call_sites.append(
            {
                "name": name,
                "line": get_node_line(node),
                "args_taint": [self.expr_taint(arg) for arg in node.args],
            }
        )

    def _check_sink(self, node: ast.Call, name: str) -> None:
        arg0 = node.args[0] if node.args else None
        arg0_taint = self.expr_taint(arg0)
        arg_repr = ast.unparse(arg0) if arg0 is not None else None

        if name in SINK_NAMES:
            trace = list(arg0_taint.trace)
            trace.append(
                TraceStep(
                    kind="sink",
                    label=name,
                    file_path=str(self.parent.module.path),
                    line=get_node_line(node),
                )
            )
            self.sink_hits.append(
                SinkHit(
                    sink_type=name,
                    sink_name=name,
                    file_path=str(self.parent.module.path),
                    line=get_node_line(node),
                    arg_tainted=arg0_taint.tainted,
                    arg_repr=arg_repr,
                    trace=trace,
                )
            )

        if name.startswith("subprocess."):
            shell_true = any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            )
            if shell_true:
                trace = list(arg0_taint.trace)
                trace.append(
                    TraceStep(
                        kind="sink",
                        label=f"{name}(shell=True)",
                        file_path=str(self.parent.module.path),
                        line=get_node_line(node),
                    )
                )
                self.sink_hits.append(
                    SinkHit(
                        sink_type="subprocess.shell",
                        sink_name=name,
                        file_path=str(self.parent.module.path),
                        line=get_node_line(node),
                        arg_tainted=arg0_taint.tainted,
                        arg_repr=arg_repr,
                        trace=trace,
                        detail={
                            "shell": True,
                            "arg_is_list": isinstance(arg0, (ast.List, ast.Tuple)),
                        },
                    )
                )

        if name.endswith(".execute") or name.endswith(".executemany"):
            trace = list(arg0_taint.trace)
            trace.append(
                TraceStep(
                    kind="sink",
                    label=name,
                    file_path=str(self.parent.module.path),
                    line=get_node_line(node),
                )
            )
            has_params = len(node.args) > 1 or any(kw.arg in {"params", "parameters"} for kw in node.keywords)
            self.sink_hits.append(
                SinkHit(
                    sink_type="sql.execute",
                    sink_name=name,
                    file_path=str(self.parent.module.path),
                    line=get_node_line(node),
                    arg_tainted=arg0_taint.tainted,
                    arg_repr=arg_repr,
                    trace=trace,
                    detail={
                        "parameterized": has_params,
                        "query_node": arg0,
                    },
                )
            )

        if name in {"open", "os.open", "pathlib.Path.open"}:
            trace = list(arg0_taint.trace)
            trace.append(
                TraceStep(
                    kind="sink",
                    label=name,
                    file_path=str(self.parent.module.path),
                    line=get_node_line(node),
                )
            )
            self.sink_hits.append(
                SinkHit(
                    sink_type="path.open",
                    sink_name=name,
                    file_path=str(self.parent.module.path),
                    line=get_node_line(node),
                    arg_tainted=arg0_taint.tainted,
                    arg_repr=arg_repr,
                    trace=trace,
                )
            )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if self.function_name is None:
            initial: dict[str, TaintInfo] = {}

            for arg in node.args.args:
                if arg.arg.startswith("request"):
                    initial[arg.arg] = TaintInfo.from_source(
                        arg.arg,
                        str(self.parent.module.path),
                        get_node_line(node),
                    )

            nested = _FunctionAnalyzer(self.parent, function_name=node.name, initial_taint=initial)
            for stmt in node.body:
                nested.visit(stmt)

            self.sink_hits.extend(nested.sink_hits)
            self.call_sites.extend(nested.call_sites)
            self.string_assignments.update(nested.string_assignments)
        else:
            for stmt in node.body:
                self.visit(stmt)


class ModuleAnalyzer:
    def __init__(self, index: ProjectIndex, module: ParsedModule) -> None:
        self.index = index
        self.module = module
        self.resolver = ImportResolver(index, module)
        self.aliases = self.resolver.resolve_aliases()

    def resolve_name(self, name: str | None) -> str | None:
        if not name:
            return None
        return self.resolver.resolve_call_target(name, self.aliases)

    def analyze(self) -> ModuleAnalysis:
        visitor = _FunctionAnalyzer(self)
        assert self.module.tree is not None
        visitor.visit(self.module.tree)

        # lightweight cross-file propagation:
        # if caller passes tainted arg to imported function and that function summary
        # shows a sink, create synthetic sink hit with trace
        for call in list(visitor.call_sites):
            name = call["name"]
            if not name:
                continue

            summary = self.index.function_summaries.get(name)
            if not summary:
                continue

            for sink_call in summary.sink_calls:
                idx = sink_call.get("arg_index", 0)
                if idx >= len(call["args_taint"]):
                    continue

                taint = call["args_taint"][idx]
                if not taint.tainted:
                    continue

                trace = list(taint.trace)
                trace.append(
                    TraceStep(
                        kind="function",
                        label=name,
                        file_path=summary.file_path,
                        line=sink_call.get("line"),
                    )
                )
                trace.append(
                    TraceStep(
                        kind="sink",
                        label=sink_call["type"],
                        file_path=summary.file_path,
                        line=sink_call.get("line"),
                    )
                )

                visitor.sink_hits.append(
                    SinkHit(
                        sink_type=sink_call["type"],
                        sink_name=name,
                        file_path=summary.file_path,
                        line=sink_call.get("line") or 1,
                        arg_tainted=True,
                        arg_repr=None,
                        trace=trace,
                        detail={"cross_file": True},
                    )
                )

        return ModuleAnalysis(
            module=self.module,
            aliases=self.aliases,
            tainted_names=visitor.tainted_names,
            sink_hits=visitor.sink_hits,
            string_assignments=visitor.string_assignments,
            call_sites=visitor.call_sites,
        )