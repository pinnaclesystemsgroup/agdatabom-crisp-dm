#!/usr/bin/env python3
"""
AgCISP ADAPT-to-EPCIS 2.0 JSON-LD Translation Module
PSG-TBM-2026-001 / NIST IR 8536 / SCT4AFM

ContextItem Registry (codes 9001-9007):
  9001 stewardshipResponsibility
  9002 sensitivityClassification
  9003 intendedProcessingPurpose
  9004 authorizedRecipientRoles
  9005 retentionExpectation
  9006 originatorRole
  9007 dataProvenanceChain

rawDataHash and ecdsaSignature come from adapt_doc['attestation'],
NOT from ContextItems.
"""
import json, sys, uuid
from datetime import datetime, timezone

CI_SENSITIVITY  = 9002
CI_PURPOSE      = 9003
CI_ROLES        = 9004
CI_RETENTION    = 9005
CI_ORIGINATOR   = 9006
CI_PROVENANCE   = 9007

def get_ci(adapt_doc):
    items = {}
    for ci in adapt_doc.get("contextItems", []):
        items[ci["code"]] = ci["value"]
    for op in adapt_doc.get("operations", []):
        for ci in op.get("contextItems", []):
            items.setdefault(ci["code"], ci["value"])
    return items

def get_attestation(adapt_doc):
    a = adapt_doc.get("attestation", {})
    return {
        "hardwareRootOfTrustIdentifier": a.get(
            "hardwareRootOfTrustIdentifier", "ATECC608B:BGA153:I2C-0x60"),
        "rawDataHash": a.get(
            "rawDataHash", "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        "ecdsaSignature": a.get(
            "ecdsaSignature", "3045022100a656861557d14f0c8a3d4413fd73a32b..."),
    }

def biz_step(purpose):
    m = {
        "DataBOM_HarvestDocumentation":     "urn:epcglobal:cbv:bizstep:harvesting",
        "DataBOM_PlantingDocumentation":    "urn:epcglobal:cbv:bizstep:planting",
        "DataBOM_ApplicationDocumentation": "urn:epcglobal:cbv:bizstep:applying",
        "DataBOM_PrescriptionDelivery":     "urn:epcglobal:cbv:bizstep:inspecting",
        "DataBOM_AgronomicAnalysis":        "urn:epcglobal:cbv:bizstep:inspecting",
        "DataBOM_ResearchAnonymized":       "urn:epcglobal:cbv:bizstep:sampling",
    }
    return m.get(purpose, "urn:epcglobal:cbv:bizstep:harvesting")

def transform(adapt_json_path, output_ld_path, device_id="zti-msm8916-001"):
    with open(adapt_json_path) as f:
        doc = json.load(f)

    ci      = get_ci(doc)
    attest  = get_attestation(doc)
    purpose = ci.get(CI_PURPOSE, "DataBOM_HarvestDocumentation")
    roles   = [r.strip() for r in
               ci.get(CI_ROLES, "PRODUCER,AGRONOMIST,REGULATOR").split(",")]

    out = {
        "@context": [
            "https://ref.gs1.org/standards/epcis/2.0/epcis-context.jsonld",
            {
                "agdatabom": "https://agcisp.org/ns/wg35/stewardship#",
                "sct4afm": "https://raw.githubusercontent.com/usnistgov/SCT4AFM/main/grain-traceability-ontology/"
            }
        ],
        "id":                  f"urn:uuid:{uuid.uuid4()}",
        "type":                "ObjectEvent",
        "eventTime":           datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventTimeZoneOffset": "+00:00",
        "action":              "OBSERVE",
        "bizStep":             biz_step(purpose),
        "disposition":         "urn:epcglobal:cbv:disp:in_progress",
        "epcList": [
            "urn:epc:id:sgln:030000.00001.0",
            f"urn:agcisp:device:{device_id}"
        ],
        "readPoint": {"id": f"urn:agcisp:masked-field:{doc.get('fieldId','unknown')}"},
        "sct4afm:cyberPhysicalLink": {
            "sct4afm:hardwareRootOfTrustIdentifier": attest["hardwareRootOfTrustIdentifier"],
            "sct4afm:rawDataHash":                   attest["rawDataHash"],
            "sct4afm:ecdsaSignature":                attest["ecdsaSignature"],
        },
        "agdatabom:stewardshipMetadataProfile": {
            "agdatabom:originatorRole":            ci.get(CI_ORIGINATOR, "PRODUCER"),
            "agdatabom:sensitivityClassification": ci.get(CI_SENSITIVITY, "PRODUCER_SENSITIVE"),
            "agdatabom:intendedProcessingPurpose": purpose,
            "agdatabom:authorizedRecipientRoles":  roles,
            "agdatabom:retentionExpectation":      ci.get(CI_RETENTION, "P7Y"),
            "agdatabom:dataProvenanceChain":       ci.get(CI_PROVENANCE,
                "git://github.com/pinnaclesystemsgroup/Zero-Trust-Interceptor/commit/latest"),
        },
    }

    with open(output_ld_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"SUCCESS: {adapt_json_path} -> {output_ld_path}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python adapt_to_epcis.py <input.json> <output.jsonld> [device_id]")
        sys.exit(1)
    device = sys.argv[3] if len(sys.argv) > 3 else "zti-msm8916-001"
    transform(sys.argv[1], sys.argv[2], device)
