// DoMakeCert.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "stdio.h"
#include "conio.h"
#include "windows.h"
#include "wincrypt.h"
#include "tchar.h"

#define MAX_LENGTH 100

int SelfSignedCertificateTest(LPTSTR pszInstanceName)
{
  // CREATE KEY PAIR FOR SELF-SIGNED CERTIFICATE IN MACHINE PROFILE
  HCRYPTPROV hCryptProv = NULL;
  HCRYPTKEY hKey = NULL;
  LPTSTR szKeyContainer = _T("suwatch");

  PCCERT_CONTEXT pCertContext = NULL;
  BYTE *pbEncoded = NULL;
  HCERTSTORE hStore = NULL;
  HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey = NULL;
  BOOL fCallerFreeProvOrNCryptKey = FALSE;
  CERT_EXTENSION rgExtension[2];
  memset(&rgExtension, 0, sizeof(rgExtension));

  TCHAR ANTARES_DNS[MAX_LENGTH];
  TCHAR ANTARES_SCMDNS[MAX_LENGTH];
  TCHAR ANTARES_X500NAME[MAX_LENGTH];

  _stprintf_s(ANTARES_DNS, MAX_LENGTH, _T("*.%s.antares-test.windows-int.net"), pszInstanceName);
  _stprintf_s(ANTARES_SCMDNS, MAX_LENGTH, _T("*.scm.%s.antares-test.windows-int.net"), pszInstanceName);
  _stprintf_s(ANTARES_X500NAME, MAX_LENGTH, _T("CN=%s"), ANTARES_DNS);

  LPCTSTR pszX500 = ANTARES_X500NAME;

  __try 
  {
    // Acquire key container
    _tprintf(_T("CryptAcquireContext... "));
    if (!CryptAcquireContext(&hCryptProv, szKeyContainer, NULL, PROV_RSA_FULL, CRYPT_MACHINE_KEYSET)) 
    {
      // Error
      _tprintf(_T("Error 0x%x\n"), GetLastError());

      // Try to create a new key container
      _tprintf(_T("CryptAcquireContext... "));
      if (!CryptAcquireContext(&hCryptProv, szKeyContainer, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET | CRYPT_MACHINE_KEYSET))
      {
        // Error
        _tprintf(_T("Error 0x%x\n"), GetLastError());
        return 0;
      }
      else 
      {
        _tprintf(_T("Success\n"));
      }
    }
    else
    {
      _tprintf(_T("Success\n"));
    }

    // Generate new key pair
    _tprintf(_T("CryptGenKey... "));
    //if (!CryptGenKey(hCryptProv, AT_SIGNATURE, 0x08000000 /*RSA-2048-BIT_KEY*/, &hKey))
    if (!CryptGenKey(hCryptProv, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &hKey))
    {
      // Error
      _tprintf(_T("Error 0x%x\n"), GetLastError());
      return 0;
    }
    else
    {
      _tprintf(_T("Success\n"));
    }

    DWORD cbEncoded = 0;
    _tprintf(_T("CertStrToName... "));
    if (!CertStrToName(X509_ASN_ENCODING, pszX500, CERT_X500_NAME_STR, NULL, pbEncoded, &cbEncoded, NULL))
    {
      // Error
      _tprintf(_T("Error 0x%x\n"), GetLastError());
      return 0;
    }
    else
    {
      _tprintf(_T("Success\n"));
    }

    _tprintf(_T("malloc... "));
    if (!(pbEncoded = (BYTE *)malloc(cbEncoded)))
    {
      // Error
      _tprintf(_T("Error 0x%x\n"), GetLastError());
      return 0;
    }
    else
    {
      _tprintf(_T("Success\n"));
    }

    _tprintf(_T("CertStrToName... "));
    if (!CertStrToName(X509_ASN_ENCODING, pszX500, CERT_X500_NAME_STR, NULL, pbEncoded, &cbEncoded, NULL))
    {
      // Error
      _tprintf(_T("Error 0x%x\n"), GetLastError());
      return 0;
    }
    else
    {
      _tprintf(_T("Success\n"));
    }

    // Prepare certificate Subject for self-signed certificate
    CERT_NAME_BLOB SubjectIssuerBlob;
    memset(&SubjectIssuerBlob, 0, sizeof(SubjectIssuerBlob));
    SubjectIssuerBlob.cbData = cbEncoded;
    SubjectIssuerBlob.pbData = pbEncoded;

    // Prepare key provider structure for self-signed certificate
    CRYPT_KEY_PROV_INFO KeyProvInfo;
    memset(&KeyProvInfo, 0, sizeof(KeyProvInfo));
    KeyProvInfo.pwszContainerName = szKeyContainer;
    KeyProvInfo.pwszProvName = NULL;
    KeyProvInfo.dwProvType = PROV_RSA_FULL;
    KeyProvInfo.dwFlags = CRYPT_MACHINE_KEYSET;
    KeyProvInfo.cProvParam = 0;
    KeyProvInfo.rgProvParam = NULL;
    KeyProvInfo.dwKeySpec = AT_KEYEXCHANGE; //AT_SIGNATURE;

    // Prepare algorithm structure for self-signed certificate
    CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
    memset(&SignatureAlgorithm, 0, sizeof(SignatureAlgorithm));
    SignatureAlgorithm.pszObjId = szOID_RSA_SHA1RSA;

    // Prepare Expiration date for self-signed certificate
    SYSTEMTIME EndTime;
    GetSystemTime(&EndTime);
    EndTime.wYear += 5;

    CERT_ALT_NAME_ENTRY NameEntries[2];
    memset(&NameEntries, 0, sizeof(NameEntries));
    NameEntries[0].dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
    NameEntries[0].pwszDNSName = ANTARES_DNS;
    NameEntries[1].dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
    NameEntries[1].pwszDNSName = ANTARES_SCMDNS;

    CERT_ALT_NAME_INFO NameInfo;
    memset(&NameInfo, 0, sizeof(NameInfo));
    NameInfo.cAltEntry = sizeof(NameEntries) / sizeof(CERT_ALT_NAME_ENTRY);
    NameInfo.rgAltEntry = NameEntries;

    rgExtension[0].pszObjId = szOID_SUBJECT_ALT_NAME2;
    rgExtension[0].fCritical = FALSE;
    if (!CryptEncodeObject(X509_ASN_ENCODING, rgExtension[0].pszObjId, &NameInfo, rgExtension[0].Value.pbData, &rgExtension[0].Value.cbData))
    {
      // Error
      _tprintf(_T("Error 0x%x\n"), GetLastError());
      return 0;
    }
    _tprintf(_T("malloc... "));
    if (!(rgExtension[0].Value.pbData = (BYTE *)malloc(rgExtension[0].Value.cbData)))
    {
      // Error
      _tprintf(_T("Error 0x%x\n"), GetLastError());
      return 0;
    }
    else
    {
      _tprintf(_T("Success\n"));
    }
    if (!CryptEncodeObject(X509_ASN_ENCODING, rgExtension[0].pszObjId, &NameInfo, rgExtension[0].Value.pbData, &rgExtension[0].Value.cbData))
    {
      // Error
      _tprintf(_T("Error 0x%x\n"), GetLastError());
      return 0;
    }

    LPSTR UsageIdentifier[1];
    UsageIdentifier[0] = szOID_PKIX_KP_SERVER_AUTH;
    CERT_ENHKEY_USAGE KeyUsage;
    memset(&KeyUsage, 0, sizeof(KeyUsage));
    KeyUsage.cUsageIdentifier = 1;
    KeyUsage.rgpszUsageIdentifier = UsageIdentifier;

    rgExtension[1].pszObjId = szOID_ENHANCED_KEY_USAGE;
    rgExtension[1].fCritical = FALSE;
    if (!CryptEncodeObject(X509_ASN_ENCODING, rgExtension[1].pszObjId, &KeyUsage, rgExtension[1].Value.pbData, &rgExtension[1].Value.cbData))
    {
      // Error
      _tprintf(_T("Error 0x%x\n"), GetLastError());
      return 0;
    }
    _tprintf(_T("malloc... "));
    if (!(rgExtension[1].Value.pbData = (BYTE *)malloc(rgExtension[1].Value.cbData)))
    {
      // Error
      _tprintf(_T("Error 0x%x\n"), GetLastError());
      return 0;
    }
    else
    {
      _tprintf(_T("Success\n"));
    }
    if (!CryptEncodeObject(X509_ASN_ENCODING, rgExtension[1].pszObjId, &KeyUsage, rgExtension[1].Value.pbData, &rgExtension[1].Value.cbData))
    {
      // Error
      _tprintf(_T("Error 0x%x\n"), GetLastError());
      return 0;
    }


    //rgExtension[2].pszObjId = szOID_KEY_USAGE;
    //rgExtension[2].fCritical = FALSE;



    CERT_EXTENSIONS Extensions;
    memset(&Extensions, 0, sizeof(Extensions));
    Extensions.cExtension = sizeof(rgExtension)/sizeof(rgExtension[0]);
    Extensions.rgExtension = rgExtension;

    // Create self-signed certificate
    _tprintf(_T("CertCreateSelfSignCertificate... "));
    //pCertContext = CertCreateSelfSignCertificate(NULL, &SubjectIssuerBlob, 0, &KeyProvInfo, &SignatureAlgorithm, 0, &EndTime, &Extensions);
    pCertContext = CertCreateSelfSignCertificate(hCryptProv, &SubjectIssuerBlob, 0, &KeyProvInfo, &SignatureAlgorithm, 0, &EndTime, &Extensions);
    if (!pCertContext)
    {
      // Error
      _tprintf(_T("Error 0x%x\n"), GetLastError());
      return 0;
    }
    else
    {
      _tprintf(_T("Success\n"));
    }

    // Open Root cert store in machine profile
    _tprintf(_T("CertOpenStore... "));
    hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"Root");
    if (!hStore)
    {
      // Error
      _tprintf(_T("Error 0x%x\n"), GetLastError());
      return 0;
    }
    else
    {
      _tprintf(_T("Success\n"));
    }

    // Add self-signed cert to the store
    _tprintf(_T("CertAddCertificateContextToStore... "));
    if (!CertAddCertificateContextToStore(hStore, pCertContext, CERT_STORE_ADD_REPLACE_EXISTING, 0))
    {
      // Error
      _tprintf(_T("Error 0x%x\n"), GetLastError());
      return 0;
    }
    else
    {
      _tprintf(_T("Success\n"));
    }

    // Just for testing, verify that we can access self-signed cert's private key
    DWORD dwKeySpec;
    _tprintf(_T("CryptAcquireCertificatePrivateKey... "));
    if (!CryptAcquireCertificatePrivateKey(pCertContext, 0, NULL, &hCryptProvOrNCryptKey, &dwKeySpec, &fCallerFreeProvOrNCryptKey))
    {
      // Error
      _tprintf(_T("Error 0x%x\n"), GetLastError());
      return 0;
    }
    else
    {
      _tprintf(_T("Success\n"));
    }                                           
  }
  __finally
  {
    // Clean up
    if (rgExtension[0].Value.pbData) {
      _tprintf(_T("free... "));
      free(rgExtension[0].Value.pbData);
      _tprintf(_T("Success\n"));
    }

    if (rgExtension[1].Value.pbData) {
      _tprintf(_T("free... "));
      free(rgExtension[1].Value.pbData);
      _tprintf(_T("Success\n"));
    }

    if (pbEncoded) {
      _tprintf(_T("free... "));
      free(pbEncoded);
      _tprintf(_T("Success\n"));
    }
    
    if (hCryptProvOrNCryptKey) 
    {
      _tprintf(_T("CryptReleaseContext... "));
      CryptReleaseContext(hCryptProvOrNCryptKey, 0); 
      _tprintf(_T("Success\n"));
    }
    
    if (pCertContext)
    {
      _tprintf(_T("CertFreeCertificateContext... "));
      CertFreeCertificateContext(pCertContext);
      _tprintf(_T("Success\n"));
    }
    
    if (hStore)
    {
      _tprintf(_T("CertCloseStore... "));
      CertCloseStore(hStore, 0);
      _tprintf(_T("Success\n"));
    }

    if (hKey) 
    {
      _tprintf(_T("CryptDestroyKey... "));
      CryptDestroyKey(hKey);
      _tprintf(_T("Success\n"));
    } 
    if (hCryptProv) 
    {
      _tprintf(_T("CryptReleaseContext... "));
      CryptReleaseContext(hCryptProv, 0);
      _tprintf(_T("Success\n"));
    }
  }

  return 0;
}

int _tmain(int argc, _TCHAR* argv[])
{
    SelfSignedCertificateTest(argc > 1 ? argv[1] : _T("kudu1"));
    //_tprintf(_T("<< Press any key>>\n")); 
    //_getch();
    return 0;
}