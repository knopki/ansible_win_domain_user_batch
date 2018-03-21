#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# this is a windows documentation stub.  actual code lives in the .ps1
# file of the same name

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: win_domain_user_batch
version_added: '2.4'
short_description: Manages Windows Active Directory user accounts in batch mode
description:
     - Manages Windows Active Directory user accounts in one fast step
options:
  domain_username:
    description:
      - The username to use when interacting with AD.
      - If this is not set then the user Ansible used to log in with will be
        used instead when using CredSSP or Kerberos with credential delegation.
    version_added: '2.5'
  domain_password:
    description:
      - The password for I(username).
    version_added: '2.5'
  domain_server:
    description:
      - Specifies the Active Directory Domain Services instance to connect to.
      - Can be in the form of an FQDN or NetBIOS name.
      - If not specified then the value is based on the domain of the computer
      running PowerShell.
    version_added: '2.5'
  default_password:
    description:
      - Specifies default password for user if not set in user list
    required: true
  default_name_attr:
    description:
      - Specifies default attribute for object name
    default: 'sAMAccontName'
  default_upn_suffix:
      - Specifies default suffix for UserPrincipalName
    required: true
  users:
    - Specifies list of users:
      sAMAccountName:
        description
          - Specifies user's sAMAccountName
        required: true
      name:
        description:
          - Specifies object's name
        default: <sAMAccountName> or user's default_name_attr
      path:
        description:
          - Specifies object's path
        required: true
      state:
        description:
          - When C(present), creates or updates the user account.  When C(absent),
            removes the user account if it exists.
        choices: [ absent, present ]
        default: present
      enabled:
        description:
          - C(yes) will enable the user account.
          - C(no) will disable the account.
        type: bool
        default: 'yes'
      password:
        description:
          - Optionally set the user's password to this (plain text) value. In order
            to enable an account - I(enabled) - a password must already be
            configured on the account, or you must provide a password here,
            or set default_password.
      password_never_expires:
        description:
          - C(yes) will set the password to never expire.
          - C(no) will allow the password to expire.
        type: bool
      update_password:
        description:
          - C(always) will update passwords if they differ.
          - C(on_create) will only set the password for newly created users.
          - Note that C(always) will always report an Ansible status of 'changed'
            because we cannot determine whether the new password differs from
            the old password.
        choices: [ always, on_create ]
        default: on_create
      user_cannot_change_password:
        description:
          - C(yes) will prevent the user from changing their password.
          - C(no) will allow the user to change their password.
        type: bool
      upn:
        description:
          - Specifies UserPrincipalName of user
        default: <sAMAccountName>@<default_upn_suffix>
      clear_attributes:
        description:
          - Specifies list of attributes to be cleared
      attributes:
        description:
          - A dict of custom LDAP attributes to set on the user.
    required: true

notes:
  - Works with Windows 2016 and newer.
  - If running on a server that is not a Domain Controller, credential
    delegation through CredSSP or Kerberos with delegation must be used or the
    I(domain_username), I(domain_password) must be set.
  - Note that some individuals have confirmed successful operation on Windows
    2008R2 servers with AD and AD Web Services enabled, but this has not
    received the same degree of testing as Windows 2012R2.
author:
    - Sergey Korolev (@knopki)
    - Nick Chandler (@nwchandler)
'''

EXAMPLES = r'''
- name: Make Active Directory great again
  win_domain_user_batch:
    default_password: "{{ ad_user_default_password }}"
    default_name_attr: "displayName"
    default_upn_suffix: "example.loc"
    domain_username: EXAMPLE\admin-account
    domain_password: SomePas2w0rd
    domain_server: domain@example.loc
    users:
      - sAMAccountName: pp
        name: pp
        state: absent
        path: "OU=Administrators,OU=m1,DC=example,DC=loc"
        attributes:
          givenName: "Pavel"
          sn: "Ponomarev"
          displayName: "Pavel Ponomarev"
      - sAMAccountName: rl
        name: rl
        password_never_expires: yes
        path: "OU=Administrators,DC=example,DC=loc"
        enabled: no
        attributes:
          displayName: "rl"
      - sAMAccountName: cool_guy
        path: "OU=Users,OU=coolOU,DC=example,DC=loc"
        attributes:
          givenName: Cool
          sn: Guy
          displayName: "Cool Guy"
          department: "Cool guy department"
          title: "Boss"
          telephoneNumber: "+12 345 678 90"
          ipPhone: "32131"
          mobile: "+32 123 234 345"
          streetAddress: "{{ ad_defaults.streetAddress }}"
          l: "{{ ad_defaults.l }}"
          st: "{{ ad_defaults.st }}"
          postalCode: "{{ ad_defaults.postalCode }}"
          c: "RU"
          co: "Russia"
          countryCode: "643"
          company: "Cool guy Inc."
        clear_attributes:
          - description

- name: Changed data in active directory
  debug: msg="{{ result.diff }}"
  when: result.changed == true
'''

RETURN = r'''
changed:
    description: true if the account changed during execution
    returned: always
    type: boolean
    sample: false
diff:
    description: tree of changed data
    returned: always
    type: dict
    sample:
      cool_guy:
        path:
          new: "OU=coolOU,DC=example,DC=loc"
          old: "OU=notCoolOU,DC=example,DC=loc"
        name:
          new: "Cool Guy"
          old: "uk-bz-0123"
'''
