# frozen_string_literal: true

control 'V-225158' do
  impact 0.5
  title "The macOS system must require individuals to be authenticated with an
        individual authenticator prior to using a group authenticator."
  desc  "Administrator users must never log in directly as root. To assure
        individual accountability and prevent unauthorized access, logging in
        as root over a remote connection must be disabled. Administrators
        should only run commands as root after first authenticating with their
        individual user names and passwords."
  tag stig_id: 'AOSX-15-001100'
  tag severity: 'medium'

  describe sshd_config do
    its('PermitRootLogin') { should eq 'no' }
  end
end
