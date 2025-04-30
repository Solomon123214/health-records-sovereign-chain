;; medical-records.clar
;; This contract manages patient health records and healthcare provider access permissions
;; on the Stacks blockchain. It enables patients to maintain sovereignty over their medical
;; data while allowing secure, permissioned sharing with authorized healthcare providers.
;; The contract tracks record ownership, access permissions, and maintains an immutable
;; audit trail of all interactions with patient records.

;; =============================
;; Constants / Error Codes
;; =============================

;; General errors
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-USER-ALREADY-REGISTERED (err u101))
(define-constant ERR-USER-NOT-FOUND (err u102))
(define-constant ERR-PROVIDER-NOT-VERIFIED (err u103))

;; Record errors
(define-constant ERR-RECORD-NOT-FOUND (err u200))
(define-constant ERR-RECORD-ALREADY-EXISTS (err u201))
(define-constant ERR-UNAUTHORIZED-RECORD-ACCESS (err u202))

;; Permission errors
(define-constant ERR-PERMISSION-ALREADY-GRANTED (err u300))
(define-constant ERR-PERMISSION-NOT-FOUND (err u301))
(define-constant ERR-PERMISSION-EXPIRED (err u302))

;; Role constants
(define-constant ROLE-PATIENT u1)
(define-constant ROLE-PROVIDER u2)
(define-constant ROLE-ADMIN u3)

;; =============================
;; Data Maps and Variables
;; =============================

;; Contract administrator - initially set to contract deployer
(define-data-var contract-admin principal tx-sender)

;; User registry - stores basic info about registered users (both patients and providers)
(define-map users principal 
  {
    role: uint,              ;; ROLE-PATIENT or ROLE-PROVIDER
    is-active: bool,         ;; Whether the user is active in the system
    verified: bool,          ;; For providers: whether they've been verified
    name: (string-utf8 64),  ;; User's name
    registration-time: uint  ;; When the user registered (block height)
  }
)

;; Patient records - maps patient principal to their medical records
(define-map patient-records principal 
  {
    record-count: uint,          ;; Number of records for this patient
    last-updated: uint           ;; Block height of last update
  }
)

;; Individual medical records - keyed by patient principal and record ID
(define-map medical-records 
  { patient: principal, record-id: uint } 
  {
    title: (string-utf8 100),            ;; Record title
    record-type: (string-utf8 50),       ;; Type of medical record
    data-hash: (buff 32),                ;; Hash of encrypted off-chain data
    provider: principal,                 ;; Provider who created this record
    timestamp: uint,                     ;; When record was created (block height)
    description: (string-utf8 200)       ;; Brief description of the record
  }
)

;; Access permissions - maps patient-provider pairs to permission details
(define-map access-permissions
  { patient: principal, provider: principal }
  {
    granted-at: uint,            ;; When permission was granted (block height)
    expires-at: uint,            ;; When permission expires (block height, 0 = no expiry)
    access-level: uint,          ;; 1=read-only, 2=read-write
    specific-records: (list 20 uint)  ;; Optional list of specific record IDs (empty = all)
  }
)

;; Audit log entries for record access and modifications
(define-map audit-log
  uint  ;; Sequential log ID
  {
    patient: principal,          ;; Patient whose record was accessed
    accessor: principal,         ;; Who accessed the record
    action-type: (string-utf8 20),  ;; Type of action (view, create, update, etc.)
    record-id: uint,             ;; ID of record that was accessed (0 if not applicable)
    timestamp: uint,             ;; Block height when action occurred
    details: (string-utf8 100)   ;; Additional information about the action
  }
)

;; Global counters for sequential IDs
(define-data-var audit-log-counter uint u0)

;; =============================
;; Private Functions
;; =============================

;; Check if the caller is a registered patient
(define-private (is-patient (user principal))
  (match (map-get? users user)
    user-data (and (is-eq (get role user-data) ROLE-PATIENT) 
                   (get is-active user-data))
    false
  )
)

;; Check if the caller is a verified healthcare provider
(define-private (is-verified-provider (user principal))
  (match (map-get? users user)
    user-data (and (is-eq (get role user-data) ROLE-PROVIDER) 
                   (get is-active user-data)
                   (get verified user-data))
    false
  )
)

;; Check if the user is the contract administrator
(define-private (is-admin (user principal))
  (is-eq user (var-get contract-admin))
)

;; Check if a provider has permission to access a patient's records
(define-private (has-permission (patient principal) (provider principal))
  (match (map-get? access-permissions { patient: patient, provider: provider })
    permission-data 
      (if (and (> (get expires-at permission-data) u0)
               (< block-height (get expires-at permission-data)))
        true  ;; Valid permission exists and has not expired
        false)
    false  ;; No permission found
  )
)

;; Check if a provider has write permission for a patient's records
(define-private (has-write-permission (patient principal) (provider principal))
  (match (map-get? access-permissions { patient: patient, provider: provider })
    permission-data 
      (and 
        (or (is-eq (get expires-at permission-data) u0)
            (< block-height (get expires-at permission-data)))
        (>= (get access-level permission-data) u2))
    false
  )
)

;; Create a new audit log entry
(define-private (create-audit-log 
  (patient principal) 
  (accessor principal) 
  (action-type (string-utf8 20)) 
  (record-id uint) 
  (details (string-utf8 100)))
  
  (let ((log-id (+ (var-get audit-log-counter) u1)))
    ;; Increment the counter
    (var-set audit-log-counter log-id)
    
    ;; Create the log entry
    (map-set audit-log log-id
      {
        patient: patient,
        accessor: accessor,
        action-type: action-type,
        record-id: record-id,
        timestamp: block-height,
        details: details
      }
    )
    log-id  ;; Return the log ID
  )
)

;; =============================
;; Read-Only Functions
;; =============================

;; Get user information
(define-read-only (get-user-info (user principal))
  (map-get? users user)
)

;; Get patient record summary
(define-read-only (get-patient-record-summary (patient principal))
  (map-get? patient-records patient)
)

;; Get a specific medical record if authorized
(define-read-only (get-medical-record (patient principal) (record-id uint))
  (let ((caller tx-sender))
    (asserts! (or (is-eq patient caller)
                  (has-permission patient caller)
                  (is-admin caller))
              ERR-UNAUTHORIZED-RECORD-ACCESS)
    
    ;; Create audit log for this access
    (if (not (is-eq patient caller))
      (create-audit-log patient caller "view" record-id "Record accessed")
      u0)  ;; No need to log when patients access their own records
    
    ;; Return the record data
    (map-get? medical-records { patient: patient, record-id: record-id })
  )
)

;; Check if a provider has permission to access a patient's records
(define-read-only (check-permission (patient principal) (provider principal))
  (match (map-get? access-permissions { patient: patient, provider: provider })
    permission-data {
      has-access: (if (> (get expires-at permission-data) u0)
                     (< block-height (get expires-at permission-data))
                     true),  ;; No expiry means permanent access
      access-level: (get access-level permission-data),
      expires-at: (get expires-at permission-data),
      specific-records: (get specific-records permission-data)
    }
    { has-access: false, access-level: u0, expires-at: u0, specific-records: (list) }
  )
)

;; Get audit log entry by ID
(define-read-only (get-audit-log-entry (log-id uint))
  (map-get? audit-log log-id)
)

;; Get the total number of audit log entries
(define-read-only (get-audit-log-count)
  (var-get audit-log-counter)
)

;; =============================
;; Public Functions
;; =============================

;; Register a new patient
(define-public (register-patient (name (string-utf8 64)))
  (let ((caller tx-sender))
    ;; Check that user isn't already registered
    (asserts! (is-none (map-get? users caller)) ERR-USER-ALREADY-REGISTERED)
    
    ;; Register the patient
    (map-set users caller {
      role: ROLE-PATIENT,
      is-active: true,
      verified: true,  ;; Patients don't need verification
      name: name,
      registration-time: block-height
    })
    
    ;; Initialize empty record storage
    (map-set patient-records caller {
      record-count: u0,
      last-updated: block-height
    })
    
    ;; Log the registration
    (create-audit-log caller caller "registration" u0 "Patient registered")
    (ok true)
  )
)

;; Register a new healthcare provider (requires admin verification later)
(define-public (register-provider (name (string-utf8 64)))
  (let ((caller tx-sender))
    ;; Check that user isn't already registered
    (asserts! (is-none (map-get? users caller)) ERR-USER-ALREADY-REGISTERED)
    
    ;; Register the provider (initially unverified)
    (map-set users caller {
      role: ROLE-PROVIDER,
      is-active: true,
      verified: false,  ;; Providers need verification
      name: name,
      registration-time: block-height
    })
    
    ;; Log the registration
    (create-audit-log caller caller "registration" u0 "Provider registered (pending verification)")
    (ok true)
  )
)

;; Verify a healthcare provider (admin only)
(define-public (verify-provider (provider principal))
  (let ((caller tx-sender))
    ;; Check that caller is an admin
    (asserts! (is-admin caller) ERR-NOT-AUTHORIZED)
    
    ;; Check that provider exists
    (match (map-get? users provider)
      user-data 
        (begin
          ;; Update provider to verified status
          (map-set users provider (merge user-data { verified: true }))
          ;; Log the verification
          (create-audit-log provider caller "verification" u0 "Provider verified by admin")
          (ok true))
      (err ERR-USER-NOT-FOUND)
    )
  )
)

;; Add a new medical record for a patient
(define-public (add-medical-record
  (patient principal)
  (title (string-utf8 100))
  (record-type (string-utf8 50))
  (data-hash (buff 32))
  (description (string-utf8 200)))
  
  (let ((provider tx-sender))
    ;; Check that provider is verified
    (asserts! (is-verified-provider provider) ERR-PROVIDER-NOT-VERIFIED)
    
    ;; Check that provider has write permission
    (asserts! (has-write-permission patient provider) ERR-UNAUTHORIZED-RECORD-ACCESS)
    
    ;; Get current record count for this patient
    (match (map-get? patient-records patient)
      patient-data 
        (let ((record-id (+ (get record-count patient-data) u1)))
          ;; Update patient record counter
          (map-set patient-records patient 
            (merge patient-data { 
              record-count: record-id, 
              last-updated: block-height 
            }))
          
          ;; Create new record
          (map-set medical-records 
            { patient: patient, record-id: record-id }
            {
              title: title,
              record-type: record-type,
              data-hash: data-hash,
              provider: provider,
              timestamp: block-height,
              description: description
            }
          )
          
          ;; Log the action
          (create-audit-log patient provider "create" record-id "New record created")
          (ok record-id))
      (err ERR-USER-NOT-FOUND)
    )
  )
)

;; Update an existing medical record
(define-public (update-medical-record
  (patient principal)
  (record-id uint)
  (title (string-utf8 100))
  (data-hash (buff 32))
  (description (string-utf8 200)))
  
  (let ((provider tx-sender))
    ;; Check that provider is verified
    (asserts! (is-verified-provider provider) ERR-PROVIDER-NOT-VERIFIED)
    
    ;; Check that provider has write permission
    (asserts! (has-write-permission patient provider) ERR-UNAUTHORIZED-RECORD-ACCESS)
    
    ;; Check that record exists
    (match (map-get? medical-records { patient: patient, record-id: record-id })
      existing-record
        (begin
          ;; Update the record
          (map-set medical-records 
            { patient: patient, record-id: record-id }
            (merge existing-record {
              title: title,
              data-hash: data-hash,
              description: description,
              timestamp: block-height  ;; Update timestamp
            })
          )
          
          ;; Update patient's last-updated timestamp
          (match (map-get? patient-records patient)
            patient-data
              (map-set patient-records patient 
                (merge patient-data { last-updated: block-height }))
            (err ERR-USER-NOT-FOUND)  ;; Should never happen
          )
          
          ;; Log the update
          (create-audit-log patient provider "update" record-id "Record updated")
          (ok true))
      (err ERR-RECORD-NOT-FOUND)
    )
  )
)

;; Grant access to a healthcare provider
(define-public (grant-access 
  (provider principal) 
  (access-level uint) 
  (expires-in uint)  ;; Number of blocks until expiration, 0 for no expiry
  (specific-records (list 20 uint)))  ;; Empty list for all records
  
  (let ((patient tx-sender)
        (expiry (if (> expires-in u0) 
                  (+ block-height expires-in) 
                  u0)))
    
    ;; Check that patient is registered
    (asserts! (is-patient patient) ERR-USER-NOT-FOUND)
    
    ;; Check that provider is registered and verified
    (asserts! (is-verified-provider provider) ERR-PROVIDER-NOT-VERIFIED)
    
    ;; Set permission
    (map-set access-permissions 
      { patient: patient, provider: provider }
      {
        granted-at: block-height,
        expires-at: expiry,
        access-level: access-level,
        specific-records: specific-records
      }
    )
    
    ;; Log the permission change
    (create-audit-log 
      patient 
      patient 
      "grant-access" 
      u0 
      (concat (concat "Access granted to " (unwrap-panic (principal-to-string provider))) 
              (if (> expires-in u0) 
                (concat " for " (uint-to-string expires-in)) 
                " permanently")))
    
    (ok true)
  )
)

;; Revoke access from a healthcare provider
(define-public (revoke-access (provider principal))
  (let ((patient tx-sender))
    ;; Check that permission exists
    (asserts! (has-permission patient provider) ERR-PERMISSION-NOT-FOUND)
    
    ;; Get current permission
    (match (map-get? access-permissions { patient: patient, provider: provider })
      permission-data
        (begin
          ;; Set expiration to current block height (effectively revoking access)
          (map-set access-permissions 
            { patient: patient, provider: provider }
            (merge permission-data { expires-at: block-height })
          )
          
          ;; Log the permission change
          (create-audit-log 
            patient 
            patient 
            "revoke-access" 
            u0 
            (concat "Access revoked from " (unwrap-panic (principal-to-string provider))))
          
          (ok true))
      (err ERR-PERMISSION-NOT-FOUND)  ;; Should never happen due to has-permission check
    )
  )
)

;; Change contract administrator
(define-public (set-admin (new-admin principal))
  (begin
    (asserts! (is-admin tx-sender) ERR-NOT-AUTHORIZED)
    (var-set contract-admin new-admin)
    (ok true)
  )
)

;; Deactivate a user account (patient or provider)
(define-public (deactivate-account (user principal))
  (let ((caller tx-sender))
    ;; Check authorization (user themselves or admin)
    (asserts! (or (is-eq caller user) (is-admin caller)) ERR-NOT-AUTHORIZED)
    
    ;; Check that user exists
    (match (map-get? users user)
      user-data
        (begin
          ;; Set user to inactive
          (map-set users user (merge user-data { is-active: false }))
          
          ;; Log the deactivation
          (create-audit-log 
            user 
            caller 
            "deactivation" 
            u0 
            (if (is-eq caller user) 
              "Self-deactivated account" 
              "Admin deactivated account"))
          
          (ok true))
      (err ERR-USER-NOT-FOUND)
    )
  )
)

;; Reactivate a user account (admin only)
(define-public (reactivate-account (user principal))
  (let ((caller tx-sender))
    ;; Check admin authorization
    (asserts! (is-admin caller) ERR-NOT-AUTHORIZED)
    
    ;; Check that user exists
    (match (map-get? users user)
      user-data
        (begin
          ;; Set user to active
          (map-set users user (merge user-data { is-active: true }))
          
          ;; Log the reactivation
          (create-audit-log user caller "reactivation" u0 "Admin reactivated account")
          
          (ok true))
      (err ERR-USER-NOT-FOUND)
    )
  )
)