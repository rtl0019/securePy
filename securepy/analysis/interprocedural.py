from __future__ import annotations

import ast

from securepy.analysis.helpers import full_name
from securepy.analysis.import_resolver import ImportResolver
from securepy.models.function_summary import FunctionSummary
from securepy.scanner.project_index import ProjectIndex


class _ReturnTaintVisitor(ast.NodeVisitor):
    """
    Lightweight function summary builder.

    Goal:
    - detect whether return value may depend on tainted parameters
    - track simple propagation through assignments
    """

    def __init__(self, param_names: list[str]) -> None:
        self.param_names = param_names
        self.tainted_vars: set[str] = set(param_names)
        self.returns_tainted_from_params: set[int] = set()

    def _expr_is_tainted(self, node: ast.AST | None) -> bool:
        if node is None:
            return False

        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars

        if isinstance(node, ast.JoinedStr):
            return any(self._expr_is_tainted(v) for v in node.values)

        if isinstance(node, ast.FormattedValue):
            return self._expr_is_tainted(node.value)

        if isinstance(node, ast.BinOp):
            return self._expr_is_tainted(node.left) or self._expr_is_tainted(node.right)

        if isinstance(node, ast.Call):
            return any(self._expr_is_tainted(arg) for arg in node.args)

        if isinstance(node, ast.Attribute):
            return self._expr_is_tainted(node.value)

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self._expr_is_tainted(elt) for elt in node.elts)

        if isinstance(node, ast.Dict):
            return any(self._expr_is_tainted(k) for k in node.keys if k is not None) or any(
                self._expr_is_tainted(v) for v in node.values
            )

        return False

    def visit_Assign(self, node: ast.Assign) -> None:
        if self._expr_is_tainted(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name) and self._expr_is_tainted(node.value):
            self.tainted_vars.add(node.target.id)
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        if self._expr_is_tainted(node.value):
            for idx, param in enumerate(self.param_names):
                if param in self.tainted_vars:
                    self.returns_tainted_from_params.add(idx)
        self.generic_visit(node)


class SummaryBuilder:
    """
    Builds lightweight interprocedural summaries for project-local functions.
    """

    def __init__(self, index: ProjectIndex) -> None:
        self.index = index

    def build(self) -> None:
        for module in self.index.modules_by_name.values():
            if module.tree is None:
                continue

            resolver = ImportResolver(self.index, module)
            aliases = resolver.resolve_aliases()

            for node in ast.walk(module.tree):
                if isinstance(node, ast.FunctionDef):
                    param_names = [arg.arg for arg in node.args.args]
                    visitor = _ReturnTaintVisitor(param_names)
                    visitor.visit(node)

                    qualified_name = f"{module.module_name}.{node.name}"
                    summary = FunctionSummary(
                        qualified_name=qualified_name,
                        module_name=module.module_name,
                        file_path=str(module.path),
                        param_names=param_names,
                        returns_tainted_from_params=visitor.returns_tainted_from_params,
                        local_aliases=aliases,
                    )

                    self._collect_sink_calls(node, summary, resolver)
                    self.index.function_summaries[qualified_name] = summary

    def _collect_sink_calls(
        self,
        func_node: ast.FunctionDef,
        summary: FunctionSummary,
        resolver: ImportResolver,
    ) -> None:
        for node in ast.walk(func_node):
            if not isinstance(node, ast.Call):
                continue

            name = full_name(node.func)
            if not name:
                continue

            resolved = resolver.resolve_call_target(name, summary.local_aliases)

            if resolved in {"eval", "exec", "compile", "os.system", "os.popen"}:
                summary.sink_calls.append(
                    {
                        "type": resolved,
                        "line": getattr(node, "lineno", None),
                        "arg_index": 0,
                    }
                )

            elif resolved.endswith(".execute") or resolved.endswith(".executemany"):
                summary.sink_calls.append(
                    {
                        "type": "sql.execute",
                        "line": getattr(node, "lineno", None),
                        "arg_index": 0,
                    }
                )

            elif resolved in {"open", "os.open", "pathlib.Path.open"}:
                summary.sink_calls.append(
                    {
                        "type": "path.open",
                        "line": getattr(node, "lineno", None),
                        "arg_index": 0,
                    }
                )

            elif resolved in {"pickle.load", "pickle.loads"}:
                summary.sink_calls.append(
                    {
                        "type": resolved,
                        "line": getattr(node, "lineno", None),
                        "arg_index": 0,
                    }
                )