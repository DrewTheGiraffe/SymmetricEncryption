# Encryption Modification By Drew Burgess
# **Debug Version** 
# Use Mk-SKey.ps1 to create custom key. 
# Use OBFUSCATE.ps1 to encode / decode File Path to secure key.
cls

Function DecryptSecureString
{
  Param(
    [SecureString]$SecureString
  )
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
  $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
  return $plain
}

Function NewPasswordKey 
{
  [CmdletBinding()]
  Param(
    [SecureString]$Password,

    [String]$Salt
  )
  $saltBytes = [Text.Encoding]::ASCII.GetBytes($Salt) 
  $iterations = 1000
  $keySize = 256

  $clearPass = DecryptSecureString -SecureString $Password
  $passwordType = 'Security.Cryptography.Rfc2898DeriveBytes'
  $passwordDerive = New-Object -TypeName $passwordType `
    -ArgumentList @( 
      $clearPass, 
      $saltBytes, 
      $iterations,
      'SHA256'
    )

  $keyBytes = $passwordDerive.GetBytes($keySize / 8)
  return $keyBytes
}

Class CipherInfo
{
  [String]$CipherText
  [Byte[]]$IV
  [String]$Salt

  CipherInfo([String]$CipherText, [Byte[]]$IV, [String]$Salt)
  {
    $this.CipherText = $CipherText
    $this.IV = $IV
    $this.Salt = $Salt
  }
}

Function Protect-AesString 
{
  [CmdletBinding()]
  Param(
    [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true)]
    [String]$String,

    [Parameter(Position=1, Mandatory=$true)]
    [SecureString]$Password,

    [Parameter(Position=2)]
    [String]$Salt = 'qtsbp6j643ah8e0omygzwlv9u75xcfrk4j63fdane78w1zgxhucsytkirol0v25q',

    [Parameter(Position=3)]
    [Security.Cryptography.PaddingMode]$Padding = 'PKCS7'
  )
  Try 
  {
    $valueBytes = [Text.Encoding]::UTF8.GetBytes($String)
    [byte[]]$keyBytes = NewPasswordKey -Password $Password -Salt $Salt

    $cipher = [Security.Cryptography.SymmetricAlgorithm]::Create('AesManaged')
    $cipher.Mode = [Security.Cryptography.CipherMode]::CBC
    $cipher.Padding = $Padding
    $vectorBytes = $cipher.IV

    $encryptor = $cipher.CreateEncryptor($keyBytes, $vectorBytes)
    $stream = New-Object -TypeName IO.MemoryStream
    $writer = New-Object -TypeName Security.Cryptography.CryptoStream `
      -ArgumentList @(
        $stream,
        $encryptor,
        [Security.Cryptography.CryptoStreamMode]::Write
      )

    $writer.Write($valueBytes, 0, $valueBytes.Length)
    $writer.FlushFinalBlock()
    $encrypted = $stream.ToArray()

    $cipher.Clear()
    $stream.SetLength(0)
    $stream.Close()
    $writer.Clear()
    $writer.Close()
    $encryptedValue = [Convert]::ToBase64String($encrypted)
    New-Object -TypeName CipherInfo `
      -ArgumentList @($encryptedValue, $vectorBytes, $Salt)
  }
  Catch
  {
    Write-Error $_
  }
}

Function Unprotect-AesString 
{
  [CmdletBinding(DefaultParameterSetName='String')]
  Param(
    [Parameter(Position=0, Mandatory=$true, ParameterSetName='String')]
    [Alias('EncryptedString')]
    [String]$String,

    [Parameter(Position=1, Mandatory=$true)]
    [SecureString]$Password,

    [Parameter(Position=2, ParameterSetName='String')]
    [String]$Salt = 'qtsbp6j643ah8e0omygzwlv9u75xcfrk4j63fdane78w1zgxhucsytkirol0v25q',

    [Parameter(Position=3, Mandatory=$true, ParameterSetName='String')]
    [Alias('Vector')]
    [Byte[]]$InitializationVector,

    [Parameter(Position=0, Mandatory=$true, ParameterSetName='CipherInfo', ValueFromPipeline=$true)]
    [CipherInfo]$CipherInfo,

    [Parameter(Position=3, ParameterSetName='String')]
    [Parameter(Position=2, ParameterSetName='CipherInfo')]
    [Security.Cryptography.PaddingMode]$Padding = 'PKCS7'
  )
  Process
  {
    Try
    {
      if ($PSCmdlet.ParameterSetName -eq 'CipherInfo')
      {
        $Salt = $CipherInfo.Salt
        $InitializationVector = $CipherInfo.IV
        $String = $CipherInfo.CipherText
      }
      $iv = $InitializationVector

      $valueBytes = [Convert]::FromBase64String($String)
      $keyBytes = NewPasswordKey -Password $Password -Salt $Salt

      $cipher = [Security.Cryptography.SymmetricAlgorithm]::Create('AesManaged')
      $cipher.Mode = [Security.Cryptography.CipherMode]::CBC
      $cipher.Padding = $Padding

      $decryptor = $cipher.CreateDecryptor($keyBytes, $iv)
      $stream = New-Object -TypeName IO.MemoryStream `
        -ArgumentList @(, $valueBytes)
      $reader = New-Object -TypeName Security.Cryptography.CryptoStream `
        -ArgumentList @(
          $stream,
          $decryptor,
          [Security.Cryptography.CryptoStreamMode]::Read
        )

      $decrypted = New-Object -TypeName Byte[] -ArgumentList $valueBytes.Length
      $decryptedByteCount = $reader.Read($decrypted, 0, $decrypted.Length)
      $decryptedValue = [Text.Encoding]::UTF8.GetString(
        $decrypted,
        0,
        $decryptedByteCount
      )
      $cipher.Clear()
      $stream.SetLength(0)
      $stream.Close()
      $reader.Clear()
      $reader.Close()
      return $decryptedValue
    }
    Catch
    {
      Write-Error $_
    }
  }
}

[String]$Str = Read-Host -Prompt "Enter new String"
$Data =  ConvertTo-SecureString -AsPlainText $Public_key -Force 
$NewData = Protect-AesString -String $Str -Password $Data

$OldData = Unprotect-AesString -CipherInfo $NewData -Password $Data

 
Write-Host "`n"
Write-Host "Cypher Text String:`n$NewData"
Write-Host "`n"
Write-Host "Cypher Text String:`n$OldData"
