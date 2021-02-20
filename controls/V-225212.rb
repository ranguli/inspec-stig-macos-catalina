# frozen_string_literal: true

control 'V-225212' do
  impact 1.0
  title "The macOS system must use multifactor authentication for local and
        network access to privileged and non-privileged accounts, the
        establishment of nonlocal maintenance and diagnostic sessions, and
        authentication for remote access to privileged accounts in such a way
        that one of the factors is provided by a device separate from the
        system gaining access."
  desc  "Without the use of multifactor authentication, the ease of access to
        privileged and non-privileged functions is greatly increased.
        Multifactor authentication requires using two or more factors to achieve
        authentication. Factors include: 1) something a user knows
        (e.g., password/PIN); 2) something a user has (e.g., cryptographic
        identification device, token); and 3) something a user is
        (e.g., biometric). A privileged account is defined as an information
        system account with authorizations of a privileged user. Network access
        is defined as access to an information system by a user
        (or a process acting on behalf of a user) communicating through a
        network (e.g., local area network, wide area network, or the Internet).
        Local access is defined as access to an organizational information
        system by a user (or process acting on behalf of a user) communicating through a direct connection without the use of a network."
  tag stig_id: 'AOSX-15-002070'
  tag severity: 'high'

  describe command('/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep enforceSmartCard') do
    its('stdout.strip') { should eq 'enforceSmartCard=1' }
  end

  describe sshd_config do
    its('PasswordAuthentication') { should_not match(/yes/i) }
    its('ChallengeResponseAuthentication') { should_not match(/yes/i) }
  end
end
