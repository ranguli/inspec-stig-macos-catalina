# frozen_string_literal: true

control 'V-225144' do
  impact 0.5
  title "The macOS system must initiate session audits at system startup, using
        internal clocks with time stamps for audit records that meet a minimum
        granularity of one second and can be mapped to Coordinated Universal
        Time (UTC) or Greenwich Mean Time (GMT), to generate audit records
        containing information to establish what type of events occurred;
        the identity of any individual or process associated with the event,
        including individual identities of group account users; and establish
        where the events occurred, source of the event, and outcome of the
        events, including all account enabling actions, full-text recording of
        privileged commands, and information about the use of encryption for
        access wireless access to and from the system."
  desc  "Without establishing what type of events occurred, when they occurred,
        and by whom it would be difficult to establish, correlate, and
        investigate the events leading up to an outage or attack. Audit record
        content that may be necessary to satisfy this requirement includes,
        for example, time stamps, source and destination addresses,
        user/process identifiers, event descriptions, success/fail indications,
        filenames involved, and access control or flow control rules invoked.
        Associating event types with detected events in the operating system
        audit logs provides a means of investigating an attack, recognizing
        resource utilization or capacity thresholds, or identifying an
        improperly configured operating system."
  tag stig_id: 'AOSX-15-001003'
  tag severity: 'medium'

  describe command('launchctl print-disabled system| grep auditd') do
    its('stdout.strip') { should eq "\"com.apple.auditd\" => false" }
  end
end
