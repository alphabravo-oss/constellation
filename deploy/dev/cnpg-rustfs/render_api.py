"""Select one explicit image for the recovery API and its schema startup gate."""
import json
import pathlib
import sys


def render(raw, image):
    if not image or any(char.isspace() for char in image):
        raise ValueError("an explicit API image is required")
    decoder = json.JSONDecoder()
    items = []
    # kubectl create --dry-run emits adjacent JSON documents for a YAML stream;
    # other kubectl versions/inputs can produce a single Kubernetes List.
    while raw.strip():
        raw = raw.lstrip()
        value, end = decoder.raw_decode(raw)
        items.extend(value["items"] if value.get("kind") == "List" else [value])
        raw = raw[end:]
    deployments = [item for item in items if item.get("kind") == "Deployment"]
    if len(deployments) != 1:
        raise ValueError("expected exactly one recovery API deployment")
    spec = deployments[0]["spec"]["template"]["spec"]
    for field, name in (("containers", "api"), ("initContainers", "wait-for-migrations")):
        matches = [container for container in spec.get(field, []) if container["name"] == name]
        if len(matches) != 1:
            raise ValueError("missing or duplicate recovery container: " + name)
        matches[0]["image"] = image
        if field == "initContainers" and matches[0].get("args") != ["--check-schema"]:
            raise ValueError("recovery init container must enforce the API schema requirement")
    return {"apiVersion": "v1", "kind": "List", "items": items}


if __name__ == "__main__":
    source, destination, selected_image = sys.argv[1:]
    manifest = render(pathlib.Path(source).read_text(), selected_image)
    pathlib.Path(destination).write_text(json.dumps(manifest))
