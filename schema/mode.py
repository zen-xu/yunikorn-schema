"""A canonical schema definition for the yunikorn scheduler config file."""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, StringConstraints

SCHEMA_DRAFT = "http://json-schema.org/draft-07/schema#"

Acl = Annotated[
    str,
    StringConstraints(
        pattern=r"^\*$|^(([^,\s]+,)*[^,\s]+)?\s*((([^,\s]+,)*[^,\s]+)?)$"
    ),
]
UnsignedInt = Annotated[int, Field(strict=True, ge=0)]
UnsignedFloat = Annotated[float, Field(strict=True, ge=0)]


class StrictBaseModel(BaseModel):
    class Config:
        extra = "forbid"


##################
# Config section #
##################


class Resources(StrictBaseModel):
    """
    The resource limits to set on the queue. The definition allows for an unlimited number of types to be used.
    The mapping to "known" resources is not handled here.
    """

    guaranteed: dict[str, str] | None = Field(None, description="guaranteed resources")
    max: dict[str, str] | None = Field(None, description="max resources")


class ChildTemplate(StrictBaseModel):
    maxapplications: UnsignedInt | None = Field(
        None,
        description="the maximum number of applications that can run in the queue",
        title="MaxApplications",
    )
    properties: dict[str, str] | None = Field(
        None,
        description="a set of properties, exact definition of what can be set is not part of the yaml",
    )
    resources: Resources | None = Field(
        None, description="a resources object to specify resource limits on the queue"
    )


class Limit(StrictBaseModel):
    limit: str = Field("limit description")
    users: list[str] | None = Field(None, description="list of users")
    groups: list[str] | None = Field(None, description="list of groups")
    maxresources: dict[str, str] = Field(
        None,
        description="maximum resources as a resource object to allow for the user or group",
        title="MaxResources",
    )
    maxapplications: UnsignedInt | None = Field(
        None,
        description="maximum number of applications the user or group can have running",
        title="MaxApplications",
    )


class QueueConfig(StrictBaseModel):
    """The queue object for each queue"""

    name: str = Field(description="the name of the queue")
    parent: bool | None = Field(
        None,
        description="if a queue does not have a sub the queue in the configuration it is a leaf queue, unless the parent parameter is set to true",
    )
    resources: Resources | None = Field(
        None, description="a resources object to specify resource limits on the queue"
    )
    maxapplications: UnsignedInt | None = Field(
        None,
        description="the maximum number of applications that can run in the queue",
        title="MaxApplications",
    )
    properties: dict[str, str] | None = Field(
        None,
        description="a set of properties, exact definition of what can be set is not part of the yaml",
    )
    adminacl: Acl | None = Field(
        None, description="ACL for submit and or admin access", title="AdminACL"
    )
    submitacl: Acl | None = Field(
        None, description="ACL for submit access", title="SubmitACL"
    )
    childtemplate: ChildTemplate | None = Field(
        None,
        description="the parent queue can provide a template to define the behavior of dynamic leaf queues below it",
        title="ChildTemplate",
    )
    queues: list[QueueConfig] | None = Field(
        None, description=" a list of sub or child queues"
    )
    limits: list[Limit] | None = Field(
        None, description="a list of users specifying limits on a queue"
    )


class Filter(StrictBaseModel):
    type: Literal["allow", "deny"] = Field(description="type of filter")
    users: list[str] | None = Field(
        None, description="list of users to filter (maybe empty)"
    )
    groups: list[str] | None = Field(
        None, description="list of groups to filter (maybe empty)"
    )


class PlacementRule(StrictBaseModel):
    name: str = Field(description="the name of the rule")
    create: bool | None = Field(None, description="can the rule create a queue")
    filter: Filter | None = Field(
        None, description="user and group filter to be applied on the callers"
    )
    parent: PlacementRule | None = Field(
        None, description="rule link to allow setting a rule to generate the parent"
    )
    value: str | None = Field(
        None,
        description='value a generic value interpreted depending on the rule type (i.e queue name for the "fixed" rule) or the application label name for the "tag" rule)',
    )


class PartitionPreemptionConfig(StrictBaseModel):
    enabled: bool | None = Field(
        None,
        description="this boolean value defines the preemption behavior for the whole partition",
    )


class NodeSortingPolicy(StrictBaseModel):
    """
    Global Node Sorting Policy section
    """

    type: Literal["fair", "binpacking"] = Field(
        examples=["fair", "binpacking"],
        description="different type of policies supported.\n"
        "- 'fair': available resource, descending order.\n"
        "- 'binpacking': available resource, ascending order.\n",
    )
    resourceweights: dict[str, UnsignedFloat] = Field(
        {"vcore": 1.0, "memory": 1.0},
        description="resource weights",
        title="ResourceWeights",
    )


class PartitionConfig(StrictBaseModel):
    name: str = Field(description="the name of the partition")
    queues: list[QueueConfig] = Field(description="a list of sub or child queues")
    placementrules: list[PlacementRule] | None = Field(
        None,
        description="a list of placement rule definition objects",
        title="PlacementRules",
    )
    limits: list[Limit] | None = Field(
        None, description="a list of users specifying limits on the partition"
    )
    preemption: PartitionPreemptionConfig | None = Field(
        None, description="the preemption configuration for the partition"
    )
    nodesortpolicy: NodeSortingPolicy | None = Field(
        None,
        description="the nodesortpolicy key defines the way the nodes are sorted for the partition",
        title="NodeSortPolicy",
    )


class BaseManifest(StrictBaseModel):
    """The configuration for [`yunikorn`](https://yunikorn.apache.org) project."""

    class Config:
        json_schema_extra = {
            "$schema": SCHEMA_DRAFT,
            "title": "yunikorn config file",
        }

    partitions: list[PartitionConfig] = Field(
        description="each partition contains the queue definition for a logical set of scheduler resources.",
    )


#########################
# JSON Schema utilities #
#########################


class SchemaJsonEncoder(json.JSONEncoder):
    """A custom schema encoder for normalizing schema to be used with TOML files."""

    HEADER_ORDER = [
        "$schema",
        "$id",
        "$ref",
        "title",
        "deprecated",
        "description",
        "type",
        "required",
        "additionalProperties",
        "default",
        "items" "properties",
        "patternProperties",
        "allOf",
        "anyOf",
        "oneOf",
        "not",
        "format",
        "minimum",
        "exclusiveMinimum",
        "maximum",
        "exclusiveMaximum",
        "minLength",
        "maxLength",
        "multipleOf",
        "pattern",
    ]
    FOOTER_ORDER = [
        "examples",
        "$defs",
    ]
    SORT_NESTED = [
        "items",
    ]
    SORT_NESTED_OBJ = [
        "properties",
        "$defs",
    ]
    SORT_NESTED_MAYBE_OBJ = [
        "additionalProperties",
    ]
    SORT_NESTED_OBJ_OBJ = [
        "patternProperties",
    ]
    SORT_NESTED_ARR = [
        "anyOf",
        "allOf",
        "oneOf",
    ]

    def encode(self, obj):
        """Overload the default ``encode`` behavior."""
        if isinstance(obj, dict):
            obj = self.normalize_schema(deepcopy(obj))

        return super().encode(obj)

    def normalize_schema(self, obj: dict[str, Any]) -> dict[str, Any]:
        """Recursively normalize and apply an arbitrary sort order to a schema."""
        self.strip_nulls(obj)

        for nest in self.SORT_NESTED:
            if nest in obj:
                obj[nest] = self.normalize_schema(obj[nest])

        for nest in self.SORT_NESTED_OBJ:
            obj = self.sort_nested(obj, nest)

        for nest in self.SORT_NESTED_OBJ_OBJ:
            if nest in obj:
                obj[nest] = {
                    k: self.normalize_schema(v)
                    for k, v in sorted(obj[nest].items(), key=lambda kv: kv[0])
                }

        for nest in self.SORT_NESTED_ARR:
            if nest in obj:
                obj[nest] = [self.normalize_schema(item) for item in obj[nest]]

        for nest in self.SORT_NESTED_MAYBE_OBJ:
            if isinstance(obj.get(nest), dict):
                obj[nest] = self.normalize_schema(obj[nest])

        header = {}
        footer = {}

        for key in self.HEADER_ORDER:
            if key in obj:
                header[key] = obj.pop(key)

        for key in self.FOOTER_ORDER:
            if key in obj:
                footer[key] = obj.pop(key)

        return {**header, **dict(sorted(obj.items())), **footer}

    def strip_nulls(self, obj: dict[str, Any]) -> dict[str, Any]:
        """Remove unpresentable-in-TOML ``"anyOf":{"type": null}`` values."""

        if "default" in obj and obj["default"] is None:
            obj.pop("default")

        for nest in self.SORT_NESTED_ARR:
            some_of = [
                self.normalize_schema(option)
                for option in obj.get(nest, [])
                if option.get("type") != "null"
            ]

            if some_of:
                obj[nest] = some_of
                if len(some_of) == 1:
                    obj.update(some_of[0])
                    obj.pop(nest)

        return obj

    def sort_nested(self, obj: dict[str, Any], key: str) -> dict[str, Any]:
        """Sort a key of an object."""
        if key not in obj or not isinstance(obj[key], dict):
            return obj
        obj[key] = {
            k: self.normalize_schema(v) if isinstance(v, dict) else v
            for k, v in sorted(obj[key].items(), key=lambda kv: kv[0])
        }
        return obj


##########################
# Command Line Interface #
##########################

if __name__ == "__main__":
    print(json.dumps(BaseManifest.model_json_schema(), indent=2, cls=SchemaJsonEncoder))
