# frozen_string_literal: true

control 'V-225145' do
  impact 0.5
  title "The macOS system must shut down by default upon audit failure (unless
        availability is an overriding concern)."
  desc  "The audit service should shut down the computer if it is unable to
        audit system events. Once audit failure occurs, user and system
        activity is no longer recorded and malicious activity could go undetected.
        Audit processing failures include software/hardware errors, failures in
        the audit capturing mechanisms, and audit storage capacity being
        reached or exceeded. Responses to audit failure depend on the nature of
        the failure mode. When availability is an overriding concern, other
        approved actions in response to an audit failure are as follows: (i) If
        the failure was caused by the lack of audit record storage capacity,
        the operating system must continue generating audit records if possible
        (automatically restarting the audit service if necessary), overwriting
        the oldest audit records in a first-in-first-out manner. (ii) If audit
        records are sent to a centralized collection server and communication
        with this server is lost or the server fails, the operating system must
        queue audit records locally until communication is restored or until
        the audit records are retrieved manually. Upon restoration of the
        connection to the centralized collection server, action should be taken
        to synchronize the local audit data with the collection server."
  tag stig_id: 'AOSX-15-001010'
  tag severity: 'medium'

  describe command('grep ^policy /etc/security/audit_control | grep ahlt0') do
    its('stdout') { should_not eq '' }
  end
end
