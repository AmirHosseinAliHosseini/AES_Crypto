#include "AES.h"

#define xtime(b) ((b << 1) ^ ((b >> 7) * 0x1B));

AES::AES()
{
    Nb = 4;
    blockLen = 16;
    Nk = 0;
    Nr = 0;
    inBlock.resize(blockLen);
    roundKeys.clear();
}
AES::~AES()
{
    inBlock.clear();
    roundKeys.clear();
}

bool AES::EncryptECB(const deque<Byte> in, const deque<Byte> key, deque<Byte>& out)
{
    if (key.size() != 16 && key.size() != 24 && key.size() != 32)
        return false;
    if (in.empty())
        return false;

    Nk = key.size() / 4;
    Nr = Nk + 6;

    deque<Byte> inPadd = in;
    inPadd.resize(((in.size() + blockLen - 1) / blockLen) * blockLen);

    roundKeys.resize(4 * Nb * (Nr + 1) + 1);
    KeyExpansion(key);

    out.resize(inPadd.size());
    for (Byte i = 0; i < inPadd.size(); i += blockLen)
    {
		copy(inPadd.begin() + i, inPadd.begin() + i + blockLen, inBlock.begin());

        EncryptBlock();

		copy(inBlock.begin(), inBlock.end(), out.begin() + i);
    }

    return true;
}
bool AES::DecryptECB(const deque<Byte> in, const deque<Byte> key, deque<Byte>& out)
{
    if (key.size() != 16 && key.size() != 24 && key.size() != 32)
        return false;
    if (in.empty() || (in.size() % blockLen != 0))
        return false;

    Nk = key.size() / 4;
    Nr = Nk + 6;

    roundKeys.resize(4 * Nb * (Nr + 1) + 1);
    KeyExpansion(key);

    out.resize(in.size());
    for (Byte i = 0; i < in.size(); i += blockLen)
    {
		copy(in.begin() + i, in.begin() + i + blockLen, inBlock.begin());

        DecryptBlock();

		copy(inBlock.begin(), inBlock.end(), out.begin() + i);
    }

    return true;
}

bool AES::EncryptCBC(const deque<Byte> in, const deque<Byte> key, const deque<Byte> iv, deque<Byte>& out)
{
	if (key.size() != 16 && key.size() != 24 && key.size() != 32)
		return false;
	if (in.empty())
		return false;
	if (iv.size() != blockLen)
		return false;

	Nk = key.size() / 4;
	Nr = Nk + 6;

	deque<Byte> inPadd = in;
	inPadd.resize(((in.size() + blockLen - 1) / blockLen) * blockLen);

	roundKeys.resize(4 * Nb * (Nr + 1) + 1);
	KeyExpansion(key);

	out.resize(inPadd.size());
	size_t i, j;
	for (i = 0; i < inPadd.size(); i += blockLen)
	{
		copy(inPadd.begin() + i, inPadd.begin() + i + blockLen, inBlock.begin());

		if (i == 0)
			for (j = 0; j < blockLen; j++)
				inBlock[j] ^= iv[j];
		else
			for (j = 0; j < blockLen; j++)
				inBlock[j] ^= out[i - blockLen + j];
			
		EncryptBlock();

		copy(inBlock.begin(), inBlock.end(), out.begin() + i);
	}

	return true;
}
bool AES::DecryptCBC(const deque<Byte> in, const deque<Byte> key, const deque<Byte> iv, deque<Byte>& out)
{
	if (key.size() != 16 && key.size() != 24 && key.size() != 32)
		return false;
	if (in.empty() || (in.size() % blockLen != 0))
		return false;
	if (iv.size() != blockLen)
		return false;

	Nk = key.size() / 4;
	Nr = Nk + 6;

	roundKeys.resize(4 * Nb * (Nr + 1) + 1);
	KeyExpansion(key);

	out.resize(in.size());

	size_t i, j;
	for (i = 0; i < in.size(); i += blockLen)
	{
		copy(in.begin() + i, in.begin() + i + blockLen, inBlock.begin());

		DecryptBlock();

		copy(inBlock.begin(), inBlock.end(), out.begin() + i);

		if (i == 0)
			for (j = 0; j < blockLen; j++)
				out[j] ^= iv[j];
		else
			for (j = 0; j < blockLen; j++)
				out[i + j] ^= in[i - blockLen + j];
	}

	return true;
}

bool AES::EncryptPCBC(const deque<Byte> in, const deque<Byte> key, const deque<Byte> iv, deque<Byte>& out)
{
	if (key.size() != 16 && key.size() != 24 && key.size() != 32)
		return false;
	if (in.empty())
		return false;
	if (iv.size() != blockLen)
		return false;

	Nk = key.size() / 4;
	Nr = Nk + 6;

	deque<Byte> inPadd = in;
	inPadd.resize(((in.size() + blockLen - 1) / blockLen) * blockLen);

	roundKeys.resize(4 * Nb * (Nr + 1) + 1);
	KeyExpansion(key);

	out.resize(inPadd.size());
	size_t i, j;
	for (i = 0; i < inPadd.size(); i += blockLen)
	{
		copy(inPadd.begin() + i, inPadd.begin() + i + blockLen, inBlock.begin());

		if (i == 0)
			for (j = 0; j < blockLen; j++)
				inBlock[j] ^= iv[j];
		else
			for (j = 0; j < blockLen; j++)
				inBlock[j] ^= out[i - blockLen + j] ^ in[i - blockLen + j];

		EncryptBlock();

		copy(inBlock.begin(), inBlock.end(), out.begin() + i);
	}

	return true;
}
bool AES::DecryptPCBC(const deque<Byte> in, const deque<Byte> key, const deque<Byte> iv, deque<Byte>& out)
{
	if (key.size() != 16 && key.size() != 24 && key.size() != 32)
		return false;
	if (in.empty() || (in.size() % blockLen != 0))
		return false;
	if (iv.size() != blockLen)
		return false;

	Nk = key.size() / 4;
	Nr = Nk + 6;

	roundKeys.resize(4 * Nb * (Nr + 1) + 1);
	KeyExpansion(key);

	out.resize(in.size());

	size_t i, j;
	for (i = 0; i < in.size(); i += blockLen)
	{
		copy(in.begin() + i, in.begin() + i + blockLen, inBlock.begin());

		DecryptBlock();

		copy(inBlock.begin(), inBlock.end(), out.begin() + i);

		if (i == 0)
			for (j = 0; j < blockLen; j++)
				out[j] ^= iv[j];
		else
			for (j = 0; j < blockLen; j++)
				out[i + j] ^= in[i - blockLen + j] ^ out[i - blockLen + j];
	}

	return true;
}

bool AES::EncryptCFB(const deque<Byte> in, const deque<Byte> key, const deque<Byte> iv, deque<Byte>& out)
{
	if (key.size() != 16 && key.size() != 24 && key.size() != 32)
		return false;
	if (in.empty())
		return false;
	if (iv.size() != blockLen)
		return false;

	Nk = key.size() / 4;
	Nr = Nk + 6;

	deque<Byte> inPadd = in;
	inPadd.resize(((in.size() + blockLen - 1) / blockLen) * blockLen);

	roundKeys.resize(4 * Nb * (Nr + 1) + 1);
	KeyExpansion(key);

	out.resize(inPadd.size());
	size_t i, j;

	inBlock = iv;
	for (i = 0; i < inPadd.size(); i += blockLen)
	{
		EncryptBlock();

		for (j = 0; j < blockLen; j++)
			out[i + j] = inBlock[j] ^ inPadd[i + j];

		copy(out.begin() + i, out.begin() + i + blockLen, inBlock.begin());
	}

	out.resize(in.size());

	return true;
}
bool AES::DecryptCFB(const deque<Byte> in, const deque<Byte> key, const deque<Byte> iv, deque<Byte>& out)
{
	if (key.size() != 16 && key.size() != 24 && key.size() != 32)
		return false;
	if (in.empty())
		return false;
	if (iv.size() != blockLen)
		return false;

	Nk = key.size() / 4;
	Nr = Nk + 6;

	deque<Byte> inPadd = in;
	inPadd.resize(((in.size() + blockLen - 1) / blockLen) * blockLen);

	roundKeys.resize(4 * Nb * (Nr + 1) + 1);
	KeyExpansion(key);

	out.resize(inPadd.size());

	size_t i, j;

	inBlock = iv;
	for (i = 0; i < inPadd.size(); i += blockLen)
	{
		EncryptBlock();

		for (j = 0; j < blockLen; j++)
			out[i + j] = inBlock[j] ^ inPadd[i + j];

		copy(inPadd.begin() + i, inPadd.begin() + i + blockLen, inBlock.begin());
	}

	out.resize(in.size());

	return true;
}

bool AES::EncryptOFB(const deque<Byte> in, const deque<Byte> key, const deque<Byte> iv, deque<Byte>& out)
{
	if (key.size() != 16 && key.size() != 24 && key.size() != 32)
		return false;
	if (in.empty())
		return false;
	if (iv.size() != blockLen)
		return false;

	Nk = key.size() / 4;
	Nr = Nk + 6;

	deque<Byte> inPadd = in;
	inPadd.resize(((in.size() + blockLen - 1) / blockLen) * blockLen);

	roundKeys.resize(4 * Nb * (Nr + 1) + 1);
	KeyExpansion(key);

	out.resize(inPadd.size());
	size_t i, j;

	inBlock = iv;
	for (i = 0; i < inPadd.size(); i += blockLen)
	{
		EncryptBlock();

		for (j = 0; j < blockLen; j++)
			out[i + j] = inBlock[j] ^ inPadd[i + j];
	}

	out.resize(in.size());

	return true;
}
bool AES::DecryptOFB(const deque<Byte> in, const deque<Byte> key, const deque<Byte> iv, deque<Byte>& out)
{
	if (key.size() != 16 && key.size() != 24 && key.size() != 32)
		return false;
	if (in.empty())
		return false;
	if (iv.size() != blockLen)
		return false;

	Nk = key.size() / 4;
	Nr = Nk + 6;

	deque<Byte> inPadd = in;
	inPadd.resize(((in.size() + blockLen - 1) / blockLen) * blockLen);

	roundKeys.resize(4 * Nb * (Nr + 1) + 1);
	KeyExpansion(key);

	out.resize(inPadd.size());

	size_t i, j;

	inBlock = iv;
	for (i = 0; i < inPadd.size(); i += blockLen)
	{
		EncryptBlock();

		for (j = 0; j < blockLen; j++)
			out[i + j] = inBlock[j] ^ inPadd[i + j];
	}

	out.resize(in.size());

	return true;
}

void AES::printHexArray(const deque<Byte>& a) const
{
    cout << setfill('0') << hex;
    for (auto item : a)
        cout << setw(2) << (int)item;
    cout << endl;
}
bool AES::convertSTRtoVEC(const string& text, deque<Byte>& vec) const
{
    if (text.size() % 2)
        return false;

    vec.resize(text.size() / 2);

    Byte t = 0;
    for (size_t i = 0; i < text.size(); i++)
    {
        if (text[i] >= '0' && text[i] <= '9')
            t = text[i] - '0';
        else if (text[i] >= 'a' && text[i] <= 'f')
            t = text[i] - 'a' + 10;
        else if (text[i] >= 'A' && text[i] <= 'F')
            t = text[i] - 'A' + 10;
        vec[i / 2] <<= 4;
        vec[i / 2] |= t;
    }
    return true;
}
void AES::convertVECtoSTR(const deque<Byte>& vec, string& text) const
{
    stringstream output;
    output << setfill('0') << hex;
    for (auto item : vec)
        output << setw(2) << (int)item;
    text = output.str();
}

void AES::EncryptBlock()
{
    deque<deque<Byte>> state(4);

	size_t i, j, round;
	for (i = 0; i < state.size(); i++)
	{
		state[i].resize(Nb);
		for (j = 0; j < Nb; j++)
			state[i][j] = inBlock[i + 4 * j];
	}

    AddRoundKey(state);
    for (round = 1; round < Nr; round++)
    {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, round * 4 * Nb);
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, Nr * 4 * Nb);

    for (i = 0; i < 4; i++)
        for (j = 0; j < Nb; j++)
            inBlock[i + 4 * j] = state[i][j];

    state.clear();
}
void AES::DecryptBlock()
{
    deque<deque<Byte>> state(4);

	size_t i, j, round;
	for (i = 0; i < state.size(); i++)
	{
		state[i].resize(Nb);
		for (j = 0; j < Nb; j++)
			state[i][j] = inBlock[i + 4 * j];
	}

    AddRoundKey(state, Nr * 4 * Nb);
    for (round = Nr - 1; round > 0; round--)
    {
        InvSubBytes(state);
        InvShiftRows(state);
        AddRoundKey(state, round * 4 * Nb);
        InvMixColumns(state);
    }
    InvSubBytes(state);
    InvShiftRows(state);
    AddRoundKey(state);

    for (i = 0; i < state.size(); i++)
        for (j = 0; j < Nb; j++)
            inBlock[i + 4 * j] = state[i][j];

    state.clear();
}
void AES::KeyExpansion(const deque<Byte>& key)
{
    deque<Byte> temp(4);
    deque<Byte> rcon(4);

	copy(key.begin(), key.end(), roundKeys.begin());

    for (size_t i = key.size(); i < 4 * Nb * (Nr + 1); i++)
    {
		copy(roundKeys.begin() + i - 4, roundKeys.begin() + i, temp.begin());

        if (i / 4 % Nk == 0)
        {
            RotWord(temp);
            SubWord(temp);
            Rcon(rcon, i / key.size());
            XorWords(temp, rcon, temp);
        }
        else if (Nk > 6 && i / 4 % Nk == 4)
            SubWord(temp);

        roundKeys[i] = roundKeys[i - key.size()] ^ temp[0]; i++;
        roundKeys[i] = roundKeys[i - key.size()] ^ temp[1]; i++;
        roundKeys[i] = roundKeys[i - key.size()] ^ temp[2]; i++;
        roundKeys[i] = roundKeys[i - key.size()] ^ temp[3];
    }

    rcon.clear();
    temp.clear();
}

void AES::AddRoundKey(deque<deque<Byte>>& block, const size_t shift) const
{
    Byte i, j;
    for (i = 0; i < 4; i++)
        for (j = 0; j < Nb; j++)
            block[i][j] ^= roundKeys[shift + j * 4 + i];
}
void AES::SubBytes(deque<deque<Byte>>& block) const
{
    for (auto& items : block)
        for (auto& item : items)
            item = sBox[item];
}
void AES::ShiftRows(deque<deque<Byte>>& block) const
{
    ShiftRow(block[1], 1);
    ShiftRow(block[2], 2);
    ShiftRow(block[3], 3);
}
void AES::MixColumns(deque<deque<Byte>>& block) const
{
    deque<Byte> temp(4);

    Byte i, j;
    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 4; ++j)
            temp[j] = block[j][i];

        MixSingleColumn(temp);

        for (j = 0; j < 4; ++j)
            block[j][i] = temp[j];
    }
    temp.clear();
}
void AES::InvSubBytes(deque<deque<Byte>>& block) const
{
    for (auto& items : block)
        for (auto& item : items)
            item = invSBox[item];
}
void AES::InvShiftRows(deque<deque<Byte>>& block) const
{
    ShiftRow(block[1], Nb - 1);
    ShiftRow(block[2], Nb - 2);
    ShiftRow(block[3], Nb - 3);
}
void AES::InvMixColumns(deque<deque<Byte>>& block) const
{
    deque<Byte> s(4), s1(4);
    Byte i, j;

    for (j = 0; j < Nb; j++)
    {
        for (i = 0; i < 4; i++)
            s[i] = block[i][j];

        s1[0] = mulBytes(0xE, s[0]) ^ mulBytes(0xB, s[1]) ^ mulBytes(0xD, s[2]) ^ mulBytes(0x9, s[3]);
        s1[1] = mulBytes(0x9, s[0]) ^ mulBytes(0xE, s[1]) ^ mulBytes(0xB, s[2]) ^ mulBytes(0xD, s[3]);
        s1[2] = mulBytes(0xD, s[0]) ^ mulBytes(0x9, s[1]) ^ mulBytes(0xE, s[2]) ^ mulBytes(0xB, s[3]);
        s1[3] = mulBytes(0xB, s[0]) ^ mulBytes(0xD, s[1]) ^ mulBytes(0x9, s[2]) ^ mulBytes(0xE, s[3]);

        for (i = 0; i < 4; i++)
            block[i][j] = s1[i];
    }
}

void AES::RotWord(deque<Byte>& a) const
{
	a.push_back(a.front());
	a.pop_front();
}
void AES::SubWord(deque<Byte>& a) const
{
    for (auto& item : a)
        item = sBox[item];
}
void AES::Rcon(deque<Byte>& a, size_t n) const
{
    Byte i, c = 1;
    for (i = 0; i < n - 1; i++)
        c = xtime(c);

    a[0] = c;
    a[1] = a[2] = a[3] = 0;
}
void AES::XorWords(const deque<Byte> a, const deque<Byte> b, deque<Byte>& c) const
{
    for (Byte i = 0; i < 4; i++)
        c[i] = a[i] ^ b[i];
}
Byte AES::mulBytes(Byte a, Byte b) const
{
    Byte p = 0, i, modulo = 0x1B;
    Byte high_bit_mask = 0x80;
    Byte high_bit = 0;

    for (i = 0; i < 8; i++)
    {
        if (b & 1)
            p ^= a;

        high_bit = a & high_bit_mask;
        a <<= 1;
        if (high_bit)
            a ^= modulo;

        b >>= 1;
    }

    return p;
}

void AES::ShiftRow(deque<Byte>& row, int n) const
{
	while (n--)
	{
		row.push_back(row.front());
		row.pop_front();
	}
}
void AES::MixSingleColumn(deque<Byte>& r) const
{
    deque<Byte> a = r;
    deque<Byte> b(4);
    Byte c, h;

    for (c = 0; c < 4; c++)
    {
        h = (Byte)((signed char)r[c] >> 7);
        b[c] = r[c] << 1;
        b[c] ^= 0x1B & h;
    }
    r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
    r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
    r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
    r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];

    a.clear();
    b.clear();
}