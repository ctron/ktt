# Kicking the tires … of a binary

Get some dependency information on a Rust binary.

**NOTE:** Currently this isn't more than a PoC.

## Usage

Assuming you have a Rust binary built using `cargo auditable build`, you can do something like this:

```
$ ktt sbom target/debug/markdown-test-report
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.3",
  "version": 1,
  "serialNumber": "urn:uuid:8c7d9be6-c6da-4a97-9354-4f343580e821",
  "metadata": {
    "timestamp": "2023-01-10T12:21:22.768300706Z",
    "tools": [
      {
        "name": "autocfg",
        "version": "1.1.0"
      },
      {
        "name": "cc",
        "version": "1.0.77"
      },
      {
        "name": "jobserver",
        "version": "0.1.25"
      },
      {
        "name": "pkg-config",
        "version": "0.3.26"
      },
      {
        "name": "version_check",
        "version": "0.9.4"
      },
      {
        "name": "ktt",
        "version": "0.1.0"
      }
    ],
    "component": {
      "type": "application",
      "name": "markdown-test-report",
      "version": "0.3.6",
      "scope": "required"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "anyhow",
      "version": "1.0.66",
      "scope": "required",
      "purl": "pkg:cargo/anyhow@1.0.66"
    },
    {
      "type": "library",
      "name": "askama_escape",
      "version": "0.10.3",
      "scope": "required",
      "purl": "pkg:cargo/askama_escape@0.10.3"
    }, 
    …
  ]
}
```