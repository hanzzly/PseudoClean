import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from c_beautifier import beautify_c_code

s1 = """int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int i; // [rsp+14h] [rbp-Ch]

  if ( argc == 2 )
  {
    if ( strlen(s: argv[1]) == 32 )
    {
      for ( i = 0; i < 0x20; ++i )
      {
        if ( rotl8(nilai: (73 * argv[1][i] + 29) ^ 0xA7, geser: i & 7) != blob[i + 5] )
        {
          printf(format: "[-] karakter ke-%u salah\\n", i);
          return 1;
        }
      }
      puts(s: "[+] Benar! Flag diterima.");
      return 0;
    }
    else
    {
      puts(s: "[-] panjang flag salah");
      return 1;
    }
  }
  else
  {
    fprintf(stream: stderr, format: "pemakaian: %s '<flag>'\\n", *argv);
    return 1;
  }
}"""

s2 = """int __fastcall main(int argc, const char **argv, const char **envp)
{
  size_t len; // rbx
  int i; // [rsp+Ch] [rbp-84h]
  char buf[48]; // [rsp+10h] [rbp-80h] BYREF
  char input[56]; // [rsp+40h] [rbp-50h] BYREF
  unsigned __int64 v8; // [rsp+78h] [rbp-18h]

  v8 = __readfsqword(0x28u);
  strcpy(buf, "CETsd` =#Wqz#WuicqO;~kbq`|!8~Wbaw`d7/u");
  prctl(option: 4, 0, 0, 0, 0);
  setbuf(stream: stdin, buf: nullptr);
  setbuf(stream: stdout, buf: nullptr);
  setbuf(stream: stderr, buf: nullptr);
  puts(s: "This time, you can't crack my strong password :P");
  printf(format: "Enter the password: ");
  __isoc99_scanf(a1: "%49s", input);
  len = strlen(s: input);
  if ( len == strlen(s: buf) )
  {
    for ( i = 0; i < strlen(s: buf); ++i )
    {
      if ( (i & 1) != 0 )
      {
        if ( ((unsigned __int8)input[i] ^ 8) != buf[i] )
        {
LABEL_5:
          puts(s: "Incorrect password.");
          return 1;
        }
      }
      else if ( ((unsigned __int8)input[i] ^ 0x10) != buf[i] )
      {
        goto LABEL_5;
      }
    }
    puts(s: "Correct password!");
  }
  else
  {
    puts(s: "Incorrect password size.");
  }
  return 0;
}"""

s3 = """__int64 __fastcall rotl8(uint8_t nilai, char geser)
{
  if ( (geser & 7) != 0 )
    return (nilai << (geser & 7)) | (unsigned int)((int)nilai >> (8 - (geser & 7)));
  else
    return nilai;
}"""

print("=== S1 (MAIN DE-PYRAMID) ===")
print(beautify_c_code(s1))

print("\n=== S2 (ALTERNATING KEYS & GOTO & CANARY) ===")
print(beautify_c_code(s2))

print("\n=== S3 (ROTL8 HELPER) ===")
print(beautify_c_code(s3))
