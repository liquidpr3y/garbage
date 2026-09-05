"""The API surface the GUI panel binds to, reduced to something diffable.

A full OpenAPI document is not a useful thing to check in: a pydantic or
FastAPI bump rewrites descriptions and `$ref` shapes and the diff is noise. But
the panel does depend on a contract, and breaking it silently is exactly the
failure this project keeps designing against -- a backend change that compiles,
passes every backend test, and leaves the Swift side reading a field that no
longer exists.

So the checked-in surface is the part the panel actually consumes: every route
by method and path, and for each, the top-level field names of its response
model. Renaming a field or dropping a route fails the build; rewording a
description does not.
"""

from __future__ import annotations

import json
from typing import Any

SURFACE_VERSION = 1


def _resolve(schema: dict[str, Any], document: dict[str, Any], depth: int = 0) -> dict[str, Any]:
    """Follow a single $ref so array/object responses expose their fields."""
    if depth > 4 or not isinstance(schema, dict):
        return {}
    ref = schema.get("$ref")
    if ref and ref.startswith("#/components/schemas/"):
        name = ref.rsplit("/", 1)[-1]
        return _resolve(
            document.get("components", {}).get("schemas", {}).get(name, {}), document, depth + 1
        )
    if schema.get("type") == "array":
        return _resolve(schema.get("items", {}), document, depth + 1)
    return schema


def _response_fields(operation: dict[str, Any], document: dict[str, Any]) -> list[str]:
    content = (
        operation.get("responses", {})
        .get("200", operation.get("responses", {}).get("201", {}))
        .get("content", {})
        .get("application/json", {})
    )
    resolved = _resolve(content.get("schema", {}), document)
    return sorted(resolved.get("properties", {}))


def build_surface(app: Any) -> dict[str, Any]:
    """Reduce a FastAPI app's OpenAPI document to the diffable contract."""
    document = app.openapi()
    routes: dict[str, Any] = {}

    for path, operations in sorted(document.get("paths", {}).items()):
        for method, operation in sorted(operations.items()):
            if method.upper() not in ("GET", "POST", "PATCH", "PUT", "DELETE"):
                continue
            key = f"{method.upper()} {path}"
            routes[key] = {
                "response_fields": _response_fields(operation, document),
                "required_headers": sorted(
                    p["name"]
                    for p in operation.get("parameters", [])
                    if p.get("in") == "header" and p.get("required")
                ),
                "query_params": sorted(
                    p["name"] for p in operation.get("parameters", []) if p.get("in") == "query"
                ),
            }

    return {"surface_version": SURFACE_VERSION, "routes": routes}


def surface_for_module() -> dict[str, Any]:
    """The surface as the host mounts it, prefix stripped.

    Prefix-independent on purpose: the module is a sidecar today and mounted
    in-process later, and the contract must not change when that moves.
    """
    from fastapi import FastAPI

    from necropsy.api.router import router

    app = FastAPI()
    app.include_router(router)
    return build_surface(app)


def render(surface: dict[str, Any]) -> str:
    return json.dumps(surface, indent=2, sort_keys=True) + "\n"


def diff(current: dict[str, Any], committed: dict[str, Any]) -> list[str]:
    """Human-readable breaking changes, most severe first."""
    problems: list[str] = []
    current_routes = current.get("routes", {})
    committed_routes = committed.get("routes", {})

    for route in sorted(set(committed_routes) - set(current_routes)):
        problems.append(f"REMOVED route the panel binds to: {route}")

    for route in sorted(set(committed_routes) & set(current_routes)):
        was = committed_routes[route]
        now = current_routes[route]
        for field in sorted(set(was["response_fields"]) - set(now["response_fields"])):
            problems.append(f"REMOVED field {route} -> {field}")
        for header in sorted(set(now["required_headers"]) - set(was["required_headers"])):
            problems.append(f"NEW required header on {route}: {header}")

    for route in sorted(set(current_routes) - set(committed_routes)):
        problems.append(f"added route (not breaking): {route}")

    return problems
