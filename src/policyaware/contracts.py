from __future__ import annotations

import ast
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class ToolContract:
    connector_id: str
    action: str
    parameters: list[str]
    file: str
    line: int

    @property
    def names(self) -> set[str]:
        return {
            self.action,
            f"{self.connector_id}_{self.action}",
            f"{self.connector_id}__{self.action}",
        }


@dataclass(frozen=True)
class ContractFinding:
    severity: str
    connector_id: str
    action: str
    title: str
    detail: str
    recommendation: str


@dataclass(frozen=True)
class ContractCheckReport:
    policy_file: str
    scanned_path: str
    contracts_found: int
    actions_checked: int
    findings: list[ContractFinding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not any(finding.severity in {"critical", "high"} for finding in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_file": self.policy_file,
            "scanned_path": self.scanned_path,
            "contracts_found": self.contracts_found,
            "actions_checked": self.actions_checked,
            "passed": self.passed,
            "findings": [asdict(finding) for finding in self.findings],
        }


class PolicyContractChecker:
    """Validate tool-governance YAML against Python tool contracts."""

    def check(self, path: str | Path, policy_file: str | Path) -> ContractCheckReport:
        root = Path(path).resolve()
        policy_path = Path(policy_file).resolve()
        policy = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
        policy_actions = _policy_tool_actions(policy)
        connectors = {connector_id for connector_id, _, _ in policy_actions}
        actions = {action for _, action, _ in policy_actions}
        contracts = discover_tool_contracts(root, connectors=connectors, actions=actions)
        findings: list[ContractFinding] = []

        for connector_id, action, spec in policy_actions:
            contract = _match_contract(contracts, connector_id, action)
            referenced_args = sorted(_argument_references(spec))
            if contract is None:
                findings.append(
                    ContractFinding(
                        severity="high",
                        connector_id=connector_id,
                        action=action,
                        title="Policy action has no matching Python tool contract.",
                        detail=(
                            f"Expected a function named '{action}', '{connector_id}_{action}', "
                            f"or '{connector_id}__{action}'."
                        ),
                        recommendation="Add a matching tool function or update the YAML connector/action name.",
                    )
                )
                continue

            missing_args = [arg for arg in referenced_args if arg not in contract.parameters]
            if missing_args:
                findings.append(
                    ContractFinding(
                        severity="high",
                        connector_id=connector_id,
                        action=action,
                        title="YAML argument reference is not present in Python function signature.",
                        detail=(
                            f"Policy references {', '.join(missing_args)} but "
                            f"{contract.file}:{contract.line} accepts {', '.join(contract.parameters) or 'no parameters'}."
                        ),
                        recommendation="Rename the YAML arguments.* keys or update the Python function signature.",
                    )
                )
            else:
                findings.append(
                    ContractFinding(
                        severity="info",
                        connector_id=connector_id,
                        action=action,
                        title="Policy action matches Python tool contract.",
                        detail=f"Matched {contract.file}:{contract.line}.",
                        recommendation="Keep this check in CI to prevent policy drift.",
                    )
                )

        return ContractCheckReport(
            policy_file=str(policy_path),
            scanned_path=str(root),
            contracts_found=len(contracts),
            actions_checked=len(policy_actions),
            findings=findings,
        )

    def export(self, path: str | Path, out: str | Path) -> Path:
        contracts = discover_tool_contracts(Path(path).resolve())
        output = Path(out)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps({"contracts": [asdict(contract) for contract in contracts]}, indent=2),
            encoding="utf-8",
        )
        return output


def discover_tool_contracts(
    path: str | Path,
    *,
    connectors: set[str] | None = None,
    actions: set[str] | None = None,
) -> list[ToolContract]:
    root = Path(path).resolve()
    files = [root] if root.is_file() else list(root.rglob("*.py"))
    contracts: list[ToolContract] = []
    for file in files:
        if _skip_path(file):
            continue
        try:
            tree = ast.parse(file.read_text(encoding="utf-8", errors="ignore"))
        except (SyntaxError, OSError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                contract = _contract_from_function(root, file, node, connectors=connectors, actions=actions)
                if contract:
                    contracts.append(contract)
    return contracts


def _contract_from_function(
    root: Path,
    file: Path,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    connectors: set[str] | None = None,
    actions: set[str] | None = None,
) -> ToolContract | None:
    marker = _policyaware_tool_marker(node)
    if marker:
        connector_id = str(marker.get("connector_id") or marker.get("connector") or "default")
        action = str(marker.get("action") or node.name)
    else:
        connector_id = ""
        action = node.name
        if "__" in node.name:
            connector_id, action = node.name.split("__", 1)
        elif connectors and "_" in node.name:
            prefix, suffix = node.name.split("_", 1)
            if prefix in connectors:
                connector_id, action = prefix, suffix
            elif actions and node.name in actions:
                action = node.name
            else:
                return None
        elif actions and node.name in actions:
            action = node.name
        else:
            return None
    params = [
        arg.arg
        for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        if arg.arg not in {"self", "cls", "request", "context"}
    ]
    return ToolContract(
        connector_id=connector_id,
        action=action,
        parameters=params,
        file=str(file.relative_to(root if root.is_dir() else root.parent)),
        line=node.lineno,
    )


def _policyaware_tool_marker(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, Any] | None:
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Call) and _decorator_name(decorator.func) in {
            "policyaware_tool",
            "tool_contract",
        }:
            marker: dict[str, Any] = {}
            for keyword in decorator.keywords:
                if keyword.arg and isinstance(keyword.value, ast.Constant):
                    marker[keyword.arg] = keyword.value.value
            return marker
    return None


def _decorator_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _policy_tool_actions(policy: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    actions: list[tuple[str, str, dict[str, Any]]] = []
    for connector in policy.get("connectors", []) or []:
        if not isinstance(connector, dict):
            continue
        connector_id = str(connector.get("id", ""))
        for action, spec in (connector.get("actions", {}) or {}).items():
            actions.append((connector_id, str(action), spec if isinstance(spec, dict) else {}))
    return actions


def _argument_references(spec: dict[str, Any]) -> set[str]:
    references: set[str] = set()
    for dotted_key in _walk_keys(spec):
        if dotted_key.startswith("arguments."):
            argument_key = dotted_key.removeprefix("arguments.")
            for suffix in ("_not_in", "_in", "_lte", "_gte"):
                if argument_key.endswith(suffix):
                    argument_key = argument_key[: -len(suffix)]
                    break
            if argument_key:
                references.add(argument_key.split(".", 1)[0])
    return references


def _walk_keys(value: Any) -> list[str]:
    keys: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            keys.append(str(key))
            keys.extend(_walk_keys(nested))
    elif isinstance(value, list):
        for item in value:
            keys.extend(_walk_keys(item))
    return keys


def _match_contract(
    contracts: list[ToolContract], connector_id: str, action: str
) -> ToolContract | None:
    expected_names = {action, f"{connector_id}_{action}", f"{connector_id}__{action}"}
    for contract in contracts:
        if contract.connector_id == connector_id and contract.action == action:
            return contract
        if contract.connector_id == "" and contract.action == action:
            return contract
        if contract.connector_id == connector_id and contract.names & expected_names:
            return contract
    return None


def _skip_path(path: Path) -> bool:
    return any(part in {".git", ".venv", "venv", "__pycache__", "site-packages"} for part in path.parts)
