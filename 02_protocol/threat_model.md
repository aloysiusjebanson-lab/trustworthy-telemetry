# Threat Model and Trust Boundary

## Protected assets

- Measurement records
- Device signing identity
- Stream order and completeness evidence
- Stored raw observations
- Transformation code and parameters
- Emission-factor input and metadata
- Final carbon claim and evidence bundle

## Adversary capabilities

The experimental adversary may:

- modify, replay, reorder, drop, or substitute transmitted observations;
- modify records after storage;
- replace calculation code or parameters;
- replace the declared emission-factor input;
- modify files inside a completed claim bundle;
- attempt to use a different software-held device identity.

## Out-of-scope adversary capabilities

- Extracting a non-exportable key from the secure element through invasive hardware attacks
- Compromising the host operating system below all experimental controls
- Proving or disproving accredited sensor calibration
- Observing or preventing physical meter relocation, bypass, rewiring, or environmental manipulation
- Proving that ESP32 firmware honestly acquired the sensor value

## Trust boundary

Proposed demonstrator:

```text
INA219 measurement interface
        ↓
ESP32 acquisition logic
        ↓
ATECC608 protected signing key
        ║ declared device boundary
        ↓
untrusted transport, storage, and processing environment
```

The ATECC608 protects the device key. It does not prove correct acquisition code, genuine sensor physics, or uncompromised firmware. The paper must use “hardware-protected device identity” rather than “hardware-attested measurement execution.”

## Assurance properties

| Property | Target status in paper 1 |
|---|---|
| Declared device identity | Evaluated |
| Observation integrity after signing | Evaluated |
| Replay resistance | Evaluated |
| Stream gap/reordering visibility | Evaluated |
| Stored-data integrity | Evaluated |
| Transformation code/parameter identity | Evaluated |
| Reference-data provenance | Evaluated |
| Exact claim recomputation | Evaluated |
| Firmware integrity | Not established |
| Sensor calibration | Not established unless borrowed reference evidence is available |
| Physical placement/bypass | Not established |

