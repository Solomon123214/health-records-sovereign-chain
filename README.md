# Health Records Sovereign Chain

A blockchain-based platform enabling patient sovereignty over medical records with secure, permissioned sharing capabilities on the Stacks blockchain.

## Overview

Health Records Sovereign Chain is a decentralized healthcare records management system that puts patients in control of their medical data while enabling secure collaboration with healthcare providers. The platform combines the immutability and security of blockchain technology with a sophisticated permissions system to create a trustless environment for managing sensitive health information.

### Key Features

- Patient-controlled access management
- Verified healthcare provider registry
- Immutable audit trail of all record interactions
- Flexible permission settings with time-based access control
- Secure record storage with off-chain data encryption
- Comprehensive activity logging

## Architecture

The system is built around a core smart contract that manages users, records, permissions, and audit logging. The architecture follows a role-based access control model with three primary actors: patients, healthcare providers, and administrators.

```mermaid
graph TD
    A[Patient] -->|Owns| B[Medical Records]
    A -->|Grants/Revokes| C[Access Permissions]
    D[Healthcare Provider] -->|Requests| C
    D -->|Creates/Updates| B
    E[Administrator] -->|Verifies| D
    B -->|Generates| F[Audit Log]
    C -->|Generates| F
    G[Off-chain Storage] -->|Hash Reference| B
```

### Core Components

1. **User Management**
   - Patient registration
   - Provider registration and verification
   - Account status tracking

2. **Records Management**
   - Medical record creation
   - Record updates
   - Record access control

3. **Permissions System**
   - Granular access control
   - Time-based permissions
   - Record-specific permissions

4. **Audit System**
   - Comprehensive activity logging
   - Access tracking
   - Modification history

## Contract Documentation

### Medical Records Contract

The primary contract (`medical-records.clar`) handles all core functionality:

#### Key Functions

**Patient Operations**
- `register-patient`: Register new patient account
- `grant-access`: Grant provider access to records
- `revoke-access`: Revoke provider access

**Provider Operations**
- `register-provider`: Register new healthcare provider
- `add-medical-record`: Create new medical record
- `update-medical-record`: Update existing record

**Administrative Operations**
- `verify-provider`: Verify healthcare provider credentials
- `set-admin`: Change contract administrator
- `deactivate-account`: Deactivate user account
- `reactivate-account`: Reactivate user account

## Getting Started

### Prerequisites

- Clarinet CLI installed
- Stacks wallet for deployment
- Node.js for testing environment

### Installation

1. Clone the repository
```bash
git clone <repository-url>
cd health-records-sovereign-chain
```

2. Install dependencies
```bash
clarinet install
```

3. Run tests
```bash
clarinet test
```

## Function Reference

### Patient Functions

```clarity
(register-patient (name (string-utf8 64)))
```
Registers a new patient in the system.

```clarity
(grant-access (provider principal) (access-level uint) (expires-in uint) (specific-records (list 20 uint)))
```
Grants record access to a healthcare provider.

### Provider Functions

```clarity
(add-medical-record (patient principal) (title (string-utf8 100)) (record-type (string-utf8 50)) (data-hash (buff 32)) (description (string-utf8 200)))
```
Creates a new medical record for a patient.

```clarity
(update-medical-record (patient principal) (record-id uint) (title (string-utf8 100)) (data-hash (buff 32)) (description (string-utf8 200)))
```
Updates an existing medical record.

## Development

### Testing

The contract includes comprehensive test scenarios:

1. User registration flows
2. Permission management
3. Record creation and updates
4. Access control verification
5. Audit logging validation

### Local Development

1. Start Clarinet console:
```bash
clarinet console
```

2. Deploy contract:
```bash
clarinet deploy
```

## Security Considerations

### Access Control
- All record access requires explicit permission
- Permissions can be time-limited
- Providers must be verified before accessing records

### Data Privacy
- Only record hashes are stored on-chain
- Sensitive data should be encrypted off-chain
- Access revocation is immediate and permanent

### Known Limitations
- Maximum 20 specific records per permission grant
- Provider verification cannot be automated
- No built-in data encryption