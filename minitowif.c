#include <windows.h>
#include <commctrl.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/ripemd.h>

#define WINDOW_WIDTH				500
#define WINDOW_HEIGHT				175

#define KEY_DLG_WIDTH				200
#define KEY_DLG_LENGTH				75

#define BTN_WIDTH					55
#define BTN_LENGTH					30

#define ID_WINDOW_INPUT_EDITCTL 	50
#define ID_WINDOW_WIFKEY_EDITCTL	51
#define ID_WINDOW_ADDR_EDITCTL		52

#define ID_KEY_DLG_WIFKEY_EDIT_CTL	60
#define ID_KEY_DLG_OK_BTN			61

unsigned char base58[] = 
{
	'1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',
	'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L',
	'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
	'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
	'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q', 'r',
	's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
};

/* 	
	returns 0 if not valid, 1 if valid
	expects null termination
*/

int is_valid_minikey(char *minikey)
{
	char *tmpbuf = (char *)malloc(sizeof(char) * (strlen(minikey) + 2));
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int ret;
	EVP_MD_CTX ctx;
	
	strcpy(tmpbuf, minikey);
	strcat(tmpbuf, "?");
	
	if(!EVP_DigestInit(&ctx, EVP_sha256()))
	{
		free(tmpbuf);
		return(-1);
	}
	
	// If an error occurs during EVP_DigestUpdate(),
	// call EVP_DigestFinal anyway to free resources,
	// but return error.
	// Note that EVP_DigestFinal()'s return value is
	// not documented.
	if(!EVP_DigestUpdate(&ctx, tmpbuf, strlen(tmpbuf)))
	{
		EVP_DigestFinal(&ctx, hash, &ret);
		free(tmpbuf);
		return(-1);
	}
	
	EVP_DigestFinal(&ctx, hash, &ret);
	
	free(tmpbuf);
	
	// If hash[0] is 0x00, return 1, else 0
	if(!hash[0]) return(1);
	else return(0);
}

/*
	Assumes privkey has enough room
	Does not check minikey for validity
	Expects minikey to be NULL terminated
	Returns length of private key (not NULL terminated)
*/

int minikey_to_private_key(char *minikey, unsigned char *privkey)
{
	EVP_MD_CTX ctx;
	unsigned int ret;
	
	if(!EVP_DigestInit(&ctx, EVP_sha256()))
		return(-1);
	
	if(!EVP_DigestUpdate(&ctx, minikey, strlen(minikey)))
	{
		EVP_DigestFinal(&ctx, privkey, &ret);
		return(-1);
	}
	
	EVP_DigestFinal(&ctx, privkey, &ret);
	return(ret);
}

int private_key_to_wif(char **wifkey, unsigned char *privkey, int keylen)
{
	BN_CTX *bnctx;
	int i, zeroes;
	EVP_MD_CTX ctx;
	unsigned int ret;
	BIGNUM *key, *tmp, *divisor;
	unsigned char *extkey, hash[EVP_MAX_MD_SIZE];
	
	// A Base58 private key is 50 characters
	extkey = (unsigned char *)malloc(sizeof(unsigned char) * (keylen + 50));
	
	extkey[0] = 0x80;
	memcpy(extkey + 1, privkey, keylen);
	
	// keylen is now the length of ext key
	keylen++;
	
	if(!EVP_DigestInit(&ctx, EVP_sha256()))
	{
		free(extkey);
		return(-1);
	}
	
	if(!EVP_DigestUpdate(&ctx, extkey, keylen))
	{
		EVP_DigestFinal(&ctx, hash, &ret);
		free(extkey);
		return(-1);
	}
	
	EVP_DigestFinal(&ctx, hash, &ret);
	
	if(!EVP_DigestInit(&ctx, EVP_sha256()))
	{
		free(extkey);
		return(-1);
	}
	
	if(!EVP_DigestUpdate(&ctx, hash, ret))
	{
		EVP_DigestFinal(&ctx, hash, &ret);
		free(extkey);
		return(-1);
	}
	
	EVP_DigestFinal(&ctx, hash, &ret);
	
	// Sanity check
	if(ret < 4)
	{
		free(extkey);
		return(-1);
	}
	
	memcpy(extkey + keylen, hash, 4);
	keylen += 4;
	
	// Have to skip the beginning 0x80 when counting the zeroes
	for(i = 1, zeroes = 0; i < keylen; i++)
	{
		if(!extkey[i]) zeroes++;
		else break;
	}
	
	divisor = NULL;
	
	bnctx = BN_CTX_new();
	if(!bnctx)
	{
		free(extkey);
		return(-1);
	}
	
	tmp = BN_new();
	if(!tmp)
	{
		BN_CTX_free(bnctx);
		free(extkey);
		return(-1);
	}
	
	key = BN_bin2bn(extkey, keylen, NULL);
	if(!key)
	{
		BN_CTX_free(bnctx);
		BN_free(tmp);
		free(extkey);
		return(-1);
	}
	
	if(!BN_dec2bn(&divisor, "58"))
	{
		BN_CTX_free(bnctx);
		BN_free(tmp);
		BN_free(key);
		free(extkey);
		return(-1);
	}
	
	for(i = 0; !BN_is_zero(key); i++)
	{
		if(!BN_div(key, tmp, key, divisor, bnctx))	// Is using key twice legal?
		{
			BN_CTX_free(bnctx);
			BN_free(tmp);
			BN_free(key);
			BN_free(divisor);
			free(extkey);
			return(-1);
		}
		
		if(BN_num_bytes(tmp) > 4)
		{
			BN_CTX_free(bnctx);
			BN_free(tmp);
			BN_free(key);
			BN_free(divisor);
			free(extkey);
			return(-1);
		}
		
		BN_bn2bin(tmp, (unsigned char *)&ret);
		extkey[i] = base58[ret];
	}
	
	BN_CTX_free(bnctx);
	BN_free(divisor);
	BN_free(tmp);
	BN_free(key);
	
	while(zeroes--)
		extkey[i++] = base58[0];
	
	// Note that the i++ adds an extra 1; it must be subtracted.
	keylen = i - 1;
	
	// Allocate space for final key
	*wifkey = (char *)malloc(sizeof(char) * (keylen + 2));
	
	// Copy string in reverse
	for(i = 0, zeroes = keylen; i <= keylen && zeroes >= 0; i++, zeroes--)
		(*wifkey)[i] = extkey[zeroes];
	
	// NULL terminate
	(*wifkey)[i] = 0x00;
	
	// Cleanup and return
	free(extkey);
	return(i);
}

int ecdsa_get_pubkey(unsigned char **pubkey, unsigned char *rawprivkey, int keylen)
{
	BN_CTX *ctx;
	EC_KEY *privkey;
	const EC_GROUP *group;
	EC_POINT *pubkeypoint;
	BIGNUM *bnprivkey, *bnpubkey;
	
	bnprivkey = BN_bin2bn(rawprivkey, keylen, NULL);
	privkey = EC_KEY_new_by_curve_name(NID_secp256k1);
	group = EC_KEY_get0_group(privkey);
	
	pubkeypoint = EC_POINT_new(group);
	EC_KEY_set_private_key(privkey, bnprivkey);
	
	ctx = BN_CTX_new();
	bnpubkey = BN_new();
	EC_POINT_mul(group, pubkeypoint, bnprivkey, NULL, NULL, ctx);
	bnpubkey = EC_POINT_point2bn(group, pubkeypoint, POINT_CONVERSION_UNCOMPRESSED, bnpubkey, ctx);
	
	*pubkey = (unsigned char *)malloc(sizeof(unsigned char) * (BN_num_bytes(bnpubkey) + 1));
	BN_bn2bin(bnpubkey, *pubkey);
	return(BN_num_bytes(bnpubkey));
}

int pubkey_to_address(char **address, unsigned char *pubkey, int keylen)
{
	BN_CTX *bnctx;
	int i, zeroes;
	EVP_MD_CTX ctx;
	unsigned int ret;
	BIGNUM *bnpubkey, *tmp, *divisor;
	unsigned char hash[EVP_MAX_MD_SIZE], tmp1[EVP_MAX_MD_SIZE], tmp2[EVP_MAX_MD_SIZE];
	
	EVP_DigestInit(&ctx, EVP_sha256());
	EVP_DigestUpdate(&ctx, pubkey, keylen);
	EVP_DigestFinal(&ctx, hash, &ret);
	
	RIPEMD160(hash, ret, tmp1);
	
	// 0x00 version byte for main network
	tmp2[0] = 0x00;
	memcpy(tmp2 + 1, tmp1, RIPEMD160_DIGEST_LENGTH);
	
	EVP_DigestInit(&ctx, EVP_sha256());
	EVP_DigestUpdate(&ctx, tmp2, RIPEMD160_DIGEST_LENGTH + 1);
	EVP_DigestFinal(&ctx, hash, &ret);
	
	EVP_DigestInit(&ctx, EVP_sha256());
	EVP_DigestUpdate(&ctx, hash, ret);
	EVP_DigestFinal(&ctx, tmp1, &ret);
	
	memcpy(tmp2 + RIPEMD160_DIGEST_LENGTH + 1, tmp1, 4);
	
	for(i = 0, zeroes = 0; tmp2[i] == 0x00; i++, zeroes++);
	
	bnctx = BN_CTX_new();
	tmp = BN_new();
	bnpubkey = BN_bin2bn(tmp2, RIPEMD160_DIGEST_LENGTH + 5, NULL);
	divisor = NULL;
	BN_dec2bn(&divisor, "58");
	for(i = 0; !BN_is_zero(bnpubkey); i++)
	{
		BN_div(bnpubkey, tmp, bnpubkey, divisor, bnctx);
		BN_bn2bin(tmp, (unsigned char *)&ret);
		hash[i] = base58[ret];
	}
	
	for(ret = 0; (int)ret < zeroes; ret++, i++)
		hash[i] = base58[0];
	
	keylen = i - 1;
	
	*address = (char *)malloc(sizeof(char) * (keylen + 1));
	
	// Copy in reverse
	for(i = 0, zeroes = keylen; zeroes >= 0; i++, zeroes--)
		(*address)[i] = hash[zeroes];
	
	// NULL terminate
	(*address)[i] = 0x00;
	
	return(0);
}

LRESULT WINAPI MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	HWND hInputEditCtl, hWIFKeyEditCtl, hAddrEditCtl;
	
	switch(msg)
	{
		case WM_CREATE:
		{
			RECT MainWindowRect;
			
			if(!GetClientRect(hwnd, &MainWindowRect))
			{
				MessageBox(hwnd, TEXT("Unable to get window client coordinates."), TEXT("Error"), MB_OK | MB_ICONERROR);
				return(-1);
			}
			
			hInputEditCtl = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT(""),
				WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_CENTER, (int)(MainWindowRect.right * .1),
				(int)(MainWindowRect.bottom * .3), (int)(MainWindowRect.right * .8), 20, hwnd,
				(HMENU)ID_WINDOW_INPUT_EDITCTL, GetModuleHandle(NULL), NULL);
				
			hWIFKeyEditCtl = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT(""),
				WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_CENTER | ES_READONLY, (int)(MainWindowRect.right * .1),
				(int)(MainWindowRect.bottom * .5), (int)(MainWindowRect.right * .8), 20, hwnd,
				(HMENU)ID_WINDOW_WIFKEY_EDITCTL, GetModuleHandle(NULL), NULL);
			
			hAddrEditCtl = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT(""),
				WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_CENTER | ES_READONLY, (int)(MainWindowRect.right * .1),
				(int)(MainWindowRect.bottom * .7), (int)(MainWindowRect.right * .8), 20, hwnd,
				(HMENU)ID_WINDOW_ADDR_EDITCTL, GetModuleHandle(NULL), NULL);
			
			if(!hInputEditCtl || !hWIFKeyEditCtl || !hAddrEditCtl)
			{
				MessageBox(hwnd, TEXT("Failed to create window controls."), TEXT("Error"), MB_OK | MB_ICONERROR);
				return(-1);
			}
			
			// Neither EM_LIMITTEXT nor WM_SETFONT messages return a value
			SendMessage(hInputEditCtl, EM_LIMITTEXT, 30, MAKELPARAM(FALSE, 0));
			SendMessage(hInputEditCtl, EM_SETCUEBANNER, MAKEWPARAM(FALSE, 0), (LPARAM)L"Enter minikey");
			SendMessage(hInputEditCtl, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), MAKELPARAM(FALSE, 0));
			SendMessage(hWIFKeyEditCtl, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), MAKELPARAM(FALSE, 0));
			SendMessage(hAddrEditCtl, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), MAKELPARAM(FALSE, 0));
			return(FALSE);
		}
		case WM_COMMAND:
		{
			if((HIWORD(wParam) == EN_CHANGE) && (LOWORD(wParam) == ID_WINDOW_INPUT_EDITCTL))
			{
				int len, len2;
				char MiniKey[32], *wifkey, *addr;
				unsigned char privkey[EVP_MAX_MD_SIZE], *pubkey;
				
				hInputEditCtl = GetDlgItem(hwnd, ID_WINDOW_INPUT_EDITCTL);
				hWIFKeyEditCtl = GetDlgItem(hwnd, ID_WINDOW_WIFKEY_EDITCTL);
				hAddrEditCtl = GetDlgItem(hwnd, ID_WINDOW_ADDR_EDITCTL);
				
				if(!GetWindowText(hInputEditCtl, MiniKey, 31))
				{
					SetWindowText(hWIFKeyEditCtl, TEXT("Minikey is invalid."));
					break;
				}
				
				len = is_valid_minikey(MiniKey);
				
				if(!len)
				{
					SetWindowText(hWIFKeyEditCtl, TEXT("Minikey is invalid."));
					break;
				}
				else if(len == -1)
				{
					MessageBox(hwnd, TEXT("Error checking validity of minikey."), TEXT("Error"), MB_OK | MB_ICONERROR);
					break;
				}
				
				len = minikey_to_private_key(MiniKey, privkey);
				
				if(len == -1)
				{
					MessageBox(hwnd, TEXT("Error converting minikey to a private key."), TEXT("Error"), MB_OK | MB_ICONERROR);
					break;
				}
				
				len2 = len;
				
				len = private_key_to_wif(&wifkey, privkey, len);
				
				if(len == -1)
				{
					MessageBox(hwnd, TEXT("Error converting private key to wallet import format."), TEXT("Error"), MB_OK | MB_ICONERROR);
					break;
				}
				
				len2 = ecdsa_get_pubkey(&pubkey, privkey, len2);
				
				pubkey_to_address(&addr, pubkey, len2);
				
				SetWindowTextA(hWIFKeyEditCtl, wifkey);
				SetWindowTextA(hAddrEditCtl, addr);
				
				break;
			}
			else
			{
				return(DefWindowProc(hwnd, msg, wParam, lParam));
			}
		}
		case WM_CLOSE:
		{
			DestroyWindow(hwnd);
			break;
		}
		case WM_DESTROY:
		{
			PostQuitMessage(0);
			break;
		}
		default:
			return(DefWindowProc(hwnd, msg, wParam, lParam));
	}
	return(0);
}

#ifdef __GNUC__
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance __attribute__ ((unused)), LPSTR lpCmdLine __attribute__ ((unused)), INT nCmdShow)
#else
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, INT nCmdShow)
#endif
{
	WNDCLASSEX wc;
	HWND hwnd;
	MSG msg;
	
	wc.cbSize = sizeof(WNDCLASSEX);
	wc.style = 0;
	wc.lpfnWndProc = MainWndProc;
	wc.cbClsExtra = 0;
	wc.cbWndExtra = 0;
	wc.hInstance = hInstance;
	wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
	wc.hCursor = LoadCursor(NULL, IDC_ARROW);
	wc.hbrBackground = (HBRUSH)GetStockObject(LTGRAY_BRUSH);
	wc.lpszMenuName = NULL;
	wc.lpszClassName = TEXT("Window");
	wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);
	
	if(!RegisterClassEx(&wc))
	{
		MessageBox(NULL, TEXT("Error registering main window class."), TEXT("Error"), MB_OK | MB_ICONERROR);
		return(0);
	}
	
	hwnd = CreateWindow(TEXT("Window"), TEXT("Minikey to WIF Converter"), WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, CW_USEDEFAULT,
		CW_USEDEFAULT, WINDOW_WIDTH, WINDOW_HEIGHT, NULL, NULL, hInstance, NULL);
		
	if(!hwnd)
	{
		MessageBox(NULL, TEXT("Failed to create main window."), TEXT("Error"), MB_OK | MB_ICONERROR);
		return(0);
	}
	
	SendMessage(hwnd, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), MAKELPARAM(FALSE, 0));
	ShowWindow(hwnd, nCmdShow);
	
	if(!UpdateWindow(hwnd))
	{
		MessageBox(NULL, TEXT("Failed to update main window."), TEXT("Error"), MB_OK | MB_ICONERROR);
		return(0);
	}
	
	// If GetMessage() fails it returns -1,
	// so use > 0 for the check.
	while(GetMessage(&msg, NULL, 0, 0) > 0)
	{
		if(!IsDialogMessage(hwnd, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}
	
	return((int)msg.wParam);
}
