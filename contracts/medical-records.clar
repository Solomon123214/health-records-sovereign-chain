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

;; Change contract administrator
(define-public (set-admin (new-admin principal))
  (begin
    (asserts! (is-admin tx-sender) ERR-NOT-AUTHORIZED)
    (var-set contract-admin new-admin)
    (ok true)
  )
)