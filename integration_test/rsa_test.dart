import 'dart:convert';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart';
import 'package:encrypt/encrypt.dart';
import 'package:fast_rsa/fast_rsa.dart' as fast_rsa;
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  testWidgets('decrypt with fast_rsa', (tester) async {
    const value = ''
        'MmE6EuS3geonpE9XeGdW+Zp54wr1x0pKsRTObepHRbra/BTZr1ekpfUd0oLSWXIX'
        'spwIbt5F2WWvFwqekxgjO5dML1IyGIFvdhoFftiQR2cSMjBFcEkl23e7GceB9kir'
        'gNaSmcHcuJdzTc1ussbr9yavRhvJTpNmn82M/GoyWH0AjgRsA9yVuzvsOZhCvIlW'
        '8T04Q2KB0eEwwzZZesBx8w962hDvHr0TwT4MwfnlsLrhmexxH3150kqaogQR3A3y'
        '1L8jLYwRvexyaPX5QOMD/QnNtCdR+1zY5dFJaIIz5UmmNnSfmkTPD9TvA0Y4F+H9'
        '8yz4a9JjpxyuClG2aE0Nww==';
    final encrypted = base64Decode(value);
    final decrypted =
        await fast_rsa.RSA.decryptPKCS1v15Bytes(encrypted, privateKey);
    expect(decrypted,
        [97, 98, 99, 100, 101, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97]);
  });

  testWidgets('encrypt -> decrypt with fast_rsa', (tester) async {
    final array = [
      97,
      98,
      99,
      100,
      101,
      97,
      97,
      97,
      97,
      97,
      97,
      97,
      97,
      97,
      97,
      97
    ];
    final encrypted = await fast_rsa.RSA
        .encryptPKCS1v15Bytes(Uint8List.fromList(array), publicKey);
    final decrypted =
        await fast_rsa.RSA.decryptPKCS1v15Bytes(encrypted, privateKey);
    expect(decrypted, array);
  });

  testWidgets('basic_utils -> fast_rsa fails', (tester) async {
    const str = 'abcde';
    final rsaPublicKey = CryptoUtils.rsaPublicKeyFromPem(publicKey);
    final encrypted = CryptoUtils.rsaEncrypt(str, rsaPublicKey);
    expect(() async {
      await fast_rsa.RSA.decryptPKCS1v15(encrypted, privateKey);
    }, throwsA(isA<fast_rsa.RSAException>()));
  });

  testWidgets('encrypt -> fast_rsa', (widgetTester) async {
    const plainText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit';
    final RSAPublicKey key = RSAKeyParser().parse(publicKey) as RSAPublicKey;
    final encrypter = Encrypter(RSA(publicKey: key));
    final encrypted = encrypter.encrypt(plainText);
    final result =
        await fast_rsa.RSA.decryptPKCS1v15Bytes(encrypted.bytes, privateKey);
    expect(result, plainText.codeUnits);
  });
}

const publicKey = '''
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA330sHCLGJlo2oMUXIxm+
x+0iM98m5FtYZHqhsVUSl9sUeFlqMwIOtbRHRP4lQt2emme/Nq5iZqwWytCaiueX
E8iDt1bnQL1v2TDKWKymuw5WjpEfqZiVt1jg3t6FVEQZ67knBqcAZw0shCN90jpe
GkI4JBSAS3NDiglTsoglvrkZIbb0kR3YWU8yXgXc3WBCbKLix47SVlagbkcu7zfe
eLwrD3krQcvgQ81I6LpKzwlF2TQST459ex8OSSUWf4b/mpWPYpXQa9LcSjfby35K
/86VQEzPDwPiCIHHDyIPBoWjqVwL/+Gs3I5wwSuMvZWIXK60CxhkggAjkWNJK+FT
YQIDAQAB
-----END PUBLIC KEY-----
''';

const privateKey = '''-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA330sHCLGJlo2oMUXIxm+x+0iM98m5FtYZHqhsVUSl9sUeFlq
MwIOtbRHRP4lQt2emme/Nq5iZqwWytCaiueXE8iDt1bnQL1v2TDKWKymuw5WjpEf
qZiVt1jg3t6FVEQZ67knBqcAZw0shCN90jpeGkI4JBSAS3NDiglTsoglvrkZIbb0
kR3YWU8yXgXc3WBCbKLix47SVlagbkcu7zfeeLwrD3krQcvgQ81I6LpKzwlF2TQS
T459ex8OSSUWf4b/mpWPYpXQa9LcSjfby35K/86VQEzPDwPiCIHHDyIPBoWjqVwL
/+Gs3I5wwSuMvZWIXK60CxhkggAjkWNJK+FTYQIDAQABAoIBADsYDP7Pjxd7CTDP
jIOifhi9MisHGXCOWrwO1Qxf00/GBQ6hjfw40gznw2SR0uZwVUy8nAnoaGp/nHM6
X3LVM9RuU6250+IBdT63sPlrhZa2ftqpsvaUOxpE7QjhS93xN+1lgtU2eVvGVvwF
qnJZLqLA2blollfc/YHVX4U4jMp2BpSCxpUoALM0xtQkMxr0559C9bHlXh4J8+T2
QIhSf5jFvPpupi6GqwNaFtg6BSiEkoR2nBn1rJGYdSnlLDC83Qz8Bm+trHLcHpj4
5tluw5HR8eO34U0cooEzkjgX8BYZFdKmNTRCHQ7u60apOVLp1G+8J8B5l+9aMhqX
PrnfHsECgYEA83cvDOiy75o0Ahxt3L3yqwrhsCSan682EnxktQUH/CcwCdS01zCZ
PzVXhbVYL8fCjuIhZeCh2ga8xYiUa93ei6TZzFcHfSOxjj83hlZMGqkiQZRz7r1I
kCwMvKG770w0aOFd6kgRadGt54TdLqNW3Cu7ZbDUieNrKWw3EJh4bKkCgYEA6v6z
pWrGvWKIMohPsrmgsnVKaMvUZD1SjApYslbAuBBhCnZDUngX6WYx5I2l1XCkBR0F
0BJrbTvoGdQEHZxHpizhMLV8vmCo1vUDBm63aThwrZWSsJaLgWchJ2MhIbi767w3
3dCVQQ/uBUo+j49r32LFT43+psv98mC3nRbNa/kCgYAiTb6xYPAlVmLRkVPhcFoK
w4O9H8sxiKxjumcuIkFXw+W+3NuGHnDZORjV3BFK2iiNnUr7YcUsRRq/8liHQkGj
B10wr2p8tVTFKB8YrHwYnZAYEWSsVLsupSY+RcOHGgOga3CiG/loIYURQ+UuNxF8
ACVtVJb9vq9QrNCtY+5D0QKBgElpzMGuu+vKbnYq84sIRtW5osdedjnilnk9ejws
sgROyaI1FA8diYrW7FtUjSxDBlq6mGhKeNklT/tRqv99JT0a5DcNW602EUkmPg2y
ZQYwJbN0+ODGB0sj5s2hQGaCieK5aFKZqScsTNXGPgknazHcb3vNBnMhY3JnGLWw
u/gxAoGBAKdvppslM+UcPHlPpfSv6ZV1CNB2OGGERcHgFO/L5j3zdJfisYiInSB4
jD+CFWnCqEWQZg8jXK5k6EvEii5H0XTNuQgL1Ss72s2HqEZUPXEPxjXrLqzf7bIf
Y/zbqmnaH6v/9/gY+5HK2Ve5oVjU3HkU3Y3OzfWiAj7o3D9pRAO2
-----END RSA PRIVATE KEY-----
''';
