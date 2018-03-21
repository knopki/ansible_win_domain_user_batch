# Ansible module win_domain_user_batch

## Synopsis

* Manages Windows Active Directory user accounts in one fast step.
* For one user in one step, use the [win_domain_group](http://docs.ansible.com/ansible/latest/win_domain_group_module.html) module instead.
* For local groups, use the [win_group](http://docs.ansible.com/ansible/latest/win_group_module.html#win-group) module instead.

## Options
| parameter  | required | default | choises | comments |
|---|---|---|---|---|
| domain_username | no |   |   | The username to use when interacting with AD. If this is not set then the user Ansible used to log in with will be used instead when using CredSSP or Kerberos with credential delegation. |
| domain_password | no |   |   | The password for *username* |
| domain_server | no |   |   | Specifies the Active Directory Domain Services instance to connect to. Can be in the form of an FQDN or NetBIOS name. If not specified then the value is based on the domain of the computer running PowerShell.  |
| default_password | yes | | | Specifies default password for user if not set in user list |
| default_name_attr | no | *sAMAccontName* | | Specifies default attribute for object name |
| default_upn_suffix | yes | | | Specifies default suffix for UserPrincipalName |
| users | yes | | | Specifies list of *users* (see next table) |

### Users list
| parameter  | required | default | choises | comments |
|---|---|---|---|---|
| sAMAccountName | yes | | | Specifies user's sAMAccountName |
| name | no | *sAMAccountName* or user's default_name_attr | | Specifies object's name |
| path | yes | | | Specifies object's path |
| state | no | present | absent, present | When *present*, creates or updates the user account.  When *absent*, removes the user account if it exists. |
| enabled | no | yes | yes, no | *yes* will enable the user account. *no* will disable the account. |
| password | no | *default_password* | | Optionally set the user's password to this (plain text) value. In order to enable an account - *enabled* - a password must already be configured on the account, or you must provide a password here, or set default_password. |
| password_never_expires | no | no | yes, no | *yes* will set the password to never expire. *no* will allow the password to expire. |
| update_password | no | on_create | on_create, always | *always* will update passwords if they differ. *on_create* will only set the password for newly created users. Note that *always* will always report an Ansible status of 'changed' because we cannot determine whether the new password differs from the old password. |
| user_cannot_change_password | no | | | *yes* will prevent the user from changing their password. *no* will allow the user to change their password. |
| upn | no | *sAMAccountName*@*default_upn_suffix* | | Specifies UserPrincipalName of user |
| clear_attributes | no | | | Specifies list of attributes to be cleared |
| attributes | no | | | A dict of custom LDAP attributes to set on the user. |

## Examples

```yaml
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
```

## Return Values
Common return values are documented here [Return Values](http://docs.ansible.com/ansible/latest/common_return_values.html), the following are the fields unique to this module:

| name | description | returned | type | sample |
|--|--|--|--|--|
| changed | *true* if the account changed during execution | always | boolean | *false* |
| diff | tree of changed data | always | dict of dicts | `cool_guy:`<br>&nbsp;`path:`<br>&nbsp;&nbsp;`new: "OU=coolOU,DC=example,DC=loc"`<br>&nbsp;&nbsp;`old: "OU=notCoolOU,DC=example,DC=loc"`<br>&nbsp;`name:`<br>&nbsp;&nbsp;`new: "Cool Guy"`<br>&nbsp;&nbsp;`old: "uk-bz-0123"` |

## Notes
* Works with Windows 2016 and newer.
* If running on a server that is not a Domain Controller, credential
    delegation through CredSSP or Kerberos with delegation must be used or the
    I(domain_username), I(domain_password) must be set.
* Note that some individuals have confirmed successful operation on Windows
    2012R2 servers with AD and AD Web Services enabled, but this has not
    received the same degree of testing as Windows 2016.

## Authors
 * Sergey Korolev ([@knopki](http://github.com/knopki))
 * Nick Chandler ([@nwchandler](http://github.com/nwchandler))


