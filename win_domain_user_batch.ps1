#!powershell

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# WANT_JSON
# POWERSHELL_COMMON

$result = @{
  changed = $false
  diff = @{}
}

function Update-Result ($username, $key, $old, $new) {
  $result.changed = $true
  if (-not $result.diff.containsKey($username)) {
    $result.diff[$username] = @{}
  }
  $result.diff[$username][$key] = @{
    old = $old
    new = $new
  }
}


$ErrorActionPreference = "Stop"

$params = Parse-Args $args -supports_check_mode $true
$check_mode = Get-AnsibleParam -obj $params -name "_ansible_check_mode" -default $false

# Module control parameters
$domain_username = Get-AnsibleParam -obj $params -name "domain_username" -type "str"
$domain_password = Get-AnsibleParam -obj $params -name "domain_password" -type "str" -failifempty ($domain_username -ne $null)
$domain_server = Get-AnsibleParam -obj $params -name "domain_server" -type "str"

# User account parameters
$default_password = Get-AnsibleParam -obj $params -name "default_password" -type "str" -failifempty $true
$default_name_attr = Get-AnsibleParam -obj $params -name "default_name_attr" -type "str" -default "sAMAccountName"
$default_upn_suffix = Get-AnsibleParam -obj $params -name "default_upn_suffix" -type "str" -failifempty $true

# Create user array
$users_arr = Get-AnsibleParam -obj $params -name "users" -type "list" -failifempty $true
$users = @()
foreach ($u_obj in $users_arr) {
  $u_h = @{}
  $u_obj.psobject.properties | Foreach { $u_h[$_.Name] = $_.Value }
  $u_h.sAMAccountName = Get-AnsibleParam -obj $u_h -name "sAMAccountName" -type "str" -failifempty $true
  $u_h.path = Get-AnsibleParam -obj $u_h -name "path" -type "str" -failifempty $true
  $u_h.state = Get-AnsibleParam -obj $u_h -name "state" -type "str" -default "present" -validateset "absent","present"
  $u_h.enabled = Get-AnsibleParam -obj $u_h -name "enabled" -type "bool" -default $true
  $u_h.password = Get-AnsibleParam -obj $u_h -name "password" -type "str" -default $default_password
  $u_h.password_never_expires = Get-AnsibleParam -obj $u_h -name "password_never_expires" -type "bool" -default $false
  $u_h.update_password = Get-AnsibleParam -obj $u_h -name "update_password" -type "str" -default "on_create" -validateset "on_create","always"
  $u_h.user_cannot_change_password = Get-AnsibleParam -obj $u_h -name "user_cannot_change_password" -type "bool" -default $false
  $upn = $u_h.sAMAccountName+"@"+$default_upn_suffix
  $u_h.upn = Get-AnsibleParam -obj $u_h -name "upn" -type "str" -default $upn
  $u_h.clear_attributes = Get-AnsibleParam -obj $u_h -name "clear_attributes" -type "list" -default @()

  #attrs
  if ($u_h.containsKey("attributes")) {
    $a_h = @{}
    $u_h.attributes.psobject.properties | Foreach { $a_h[$_.Name] = $_.Value }
    $u_h.attributes = $a_h
  } else {
    $u_h.attributes = @()
  }

  # object name
  $objname = $u_h.sAMAccountName
  if ($default_name_attr -ne "sAMAccountName" -and $u_h.attributes -and $u_h.attributes.containsKey($default_name_attr)) {
    $objname = $u_h.attributes[$default_name_attr]
  }
  $u_h.name = Get-AnsibleParam -obj $u_h -name "name" -type "str" -default $objname

  $users += $u_h
}


if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
  Fail-Json $result "Failed to import ActiveDirectory PowerShell module. This module should be run on a domain controller, and the ActiveDirectory module must be available."
}
Import-Module ActiveDirectory


$extra_args = @{}
if ($domain_username -ne $null) {
    $domain_password = ConvertTo-SecureString $domain_password -AsPlainText -Force
    $credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $domain_username, $domain_password
    $extra_args.Credential = $credential
}
if ($domain_server -ne $null) {
    $extra_args.Server = $domain_server
}

try {
  foreach ($user in $users) {
    if ($user.state -eq "absent") {
      # Ensure user does not exist
      try {
        $u = Get-ADUser -Identity $user.sAMAccountName -Properties * @extra_args
        Remove-ADUser $u -Confirm:$false -WhatIf:$check_mode @extra_args
        Update-Result $user.sAMAccountName "state" "present" "absent"
      } catch {
        Fail-Json $result $_.Exception.Message
      }
    } elseif ($user.state -eq "present") {

      # Get user object or create new
      $new_user = $false
      try {
        $u = Get-ADUser -Identity $user.sAMAccountName -Properties * @extra_args
      } catch {
        $new_user = $true
        New-ADUser -Name $user.name -sAMAccountName $user.sAMAccountName -Path $user.path -WhatIf:$check_mode @extra_args
        Update-Result $user.sAMAccountName "state" "absent" "present"
        $u = Get-ADUser -Identity $user.sAMAccountName -Properties * @extra_args
        $secure_password = ConvertTo-SecureString $user.password -AsPlainText -Force
        Set-ADAccountPassword -Identity $user.sAMAccountName -Reset:$true -Confirm:$false -NewPassword $secure_password -WhatIf:$check_mode @extra_args
      }

      # Set UPN
      if ($user.upn -ne $u.UserPrincipalName) {
        Set-ADUser -Identity $user.sAMAccountName -UserPrincipalName $user.upn @extra_args
        Update-Result $user.sAMAccountName "UserPrincipalName" $u.UserPrincipalName $user.upn
        $u = Get-ADUser -Identity $user.sAMAccountName -Properties * @extra_args
      }

      # Set the password if required
      if (($new_user -and $user.update_password -eq "on_create") -or $user.update_password -eq "always") {
        $secure_password = ConvertTo-SecureString $user.password -AsPlainText -Force
        Set-ADAccountPassword -Identity $user.sAMAccountName -Reset:$true -Confirm:$false -NewPassword $secure_password -WhatIf:$check_mode @extra_args
        Update-Result $user.sAMAccountName "password" "[old]" "[new]"
        $u = Get-ADUser -Identity $user.sAMAccountName -Properties * @extra_args
      }


      # Configure password policies
      if ($user.password_never_expires -and ($user.password_never_expires -ne $u.PasswordNeverExpires)) {
        Set-ADUser -Identity $user.sAMAccountName -PasswordNeverExpires $user.password_never_expires -WhatIf:$check_mode @extra_args
        Update-Result $user.sAMAccountName "PasswordNeverExpires" $u.PasswordNeverExpires $user.password_never_expires
      $u = Get-ADUser -Identity $user.sAMAccountName -Properties * @extra_args
      }
      if ($user.user_cannot_change_password -and ($user.user_cannot_change_password -ne $u.CannotChangePassword)) {
        Set-ADUser -Identity $user.sAMAccountName -CannotChangePassword $user.user_cannot_change_password -WhatIf:$check_mode @extra_args
        Update-Result $user.sAMAccountName "user_cannot_change_password" $u.CannotChangePassword $user.user_cannot_change_password
        $u = Get-ADUser -Identity $user.sAMAccountName -Properties * @extra_args
      }

      # Enable/disable
      if ($user.enabled -ne $u.Enabled) {
        Set-ADUser -Identity $user.sAMAccountName -Enabled $user.enabled -WhatIf:$check_mode @extra_args
        Update-Result $user.sAMAccountName "enabled" $u.Enabled $user.enabled
        $u = Get-ADUser -Identity $user.sAMAccountName -Properties * @extra_args
      }

      # Set additional attributes
      $set_args = $extra_args.Clone()
      $run_change = $false
      $add_attributes = @{}
      $replace_attributes = @{}
      $clear_attributes = @()
      foreach ($attribute in $user.attributes.GetEnumerator()) {
        $attribute_name = $attribute.Name
        $attribute_value = $attribute.Value
        $valid_property = [bool]($u.PSobject.Properties.name -eq $attribute_name)
        if ($valid_property) {
          $existing_value = $u.$attribute_name
          if ($existing_value -cne $attribute_value) {
            $replace_attributes[$attribute_name] = $attribute_value
            Update-Result $user.sAMAccountName $attribute_name $u.$attribute_name $attribute_value
          }
          if ($user.clear_attributes -and $user.clear_attributes.contains($attribute_name)) {
            $clear_attributes += $attribute_name
            Update-Result $user.sAMAccountName $attribute_name $attribute_value $null
          }
        } else {
          $add_attributes[$attribute_name] = $attribute_value
          Update-Result $user.sAMAccountName $attribute_name $null $attribute_value
        }

        if ($add_attributes.Count -gt 0) {
          $set_args.Add = $add_attributes
          $run_change = $true
        }
        if ($replace_attributes.Count -gt 0) {
          $set_args.Replace = $replace_attributes
          $run_change = $true
        }
        if ($clear_attributes.Count -gt 0) {
          $set_args.Clear = $clear_attributes
          $run_change = $true
        }

        if ($run_change) {
          try {
            $u = $u | Set-ADUser -WhatIf:$check_mode -PassThru @set_args
          } catch {
            Fail-Json $result "failed to change user $($username): $($_.Exception.Message)"
          }
        }
      }

      # rename object
      if ($user.name -ne $u.name) {
        $result.changed = $true
        Update-Result $user.sAMAccountName "renamed" $u.name $user.name
        $u = $u | Rename-ADObject -NewName $user.name -WhatIf:$check_mode -PassThru @extra_args
      }

      # move object
      $existing_path = $u.distinguishedName -replace ("^CN="+$u.name+",")
      if ($existing_path -ne $user.path) {
        $result.changed = $true
        Update-Result $user.sAMAccountName "path" $existing_path $user.path
        $u = $u | Move-ADObject -Targetpath $user.path -WhatIf:$check_mode -PassThru @extra_args
      }


    }
  }
} catch {
  Fail-Json $result $_.Exception.Message
}
Exit-Json $result
