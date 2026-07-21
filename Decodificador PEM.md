

# Decodificador PEM - CSR, Certificados e Chaves

Ferramenta local em HTML unico para decodificar conteudo PEM sem enviar nada
para a internet. Substitui sites como certlogik/sslshopper decoder, com a
vantagem de poder colar ate chave privada com seguranca (tudo roda no
navegador, sem backend).



Abrir o `Decodificador PEM.html` com duplo clique. Funciona offline; os quatro
arquivos precisam ficar na mesma pasta (o HTML referencia os outros por caminho
relativo). O `nucleo.js` nao toca no DOM, entao pode ser reaproveitado em outro
projeto (ex.: extensao ou automacao) sem a interface.

## O que decodifica

| Entrada | Formato |
|---|---|
| CSR | PKCS#10, incluindo `BEGIN NEW CERTIFICATE REQUEST` (Windows/IIS) |
| Certificado | X.509 v1/v3, PEM ou DER binario (.cer/.crt) |
| Chave privada | PKCS#8, PKCS#1 (RSA), SEC1 (EC), PKCS#8 criptografada (PBES2/AES) |
| Chave publica | SubjectPublicKeyInfo |
| Cadeia | PKCS#7/.p7b (lista e decodifica cada certificado) |
| CRL | issuer, datas, seriais revogados |

Aceita: colar PEM (um ou varios blocos), base64 puro sem cabecalho, hex, ou
arrastar arquivo (PEM ou DER binario).

## Recursos alem da decodificacao

- **Componentes completos das chaves (sem cortes)**: para chave privada RSA
  mostra modulus, publicExponent, privateExponent, prime1, prime2, exponent1,
  exponent2 e coefficient em hex integral - saida byte a byte identica ao
  `openssl rsa -text`. Para EC mostra priv, pub e a curva. Para chave publica
  (em CSR/certificado) o modulo integral aparece num bloco recolhivel. Cada
  bloco tem botao "copiar tudo". (Antes esses campos ficavam ocultos; foram
  liberados porque a ferramenta e 100% local.)
- **Verificacao de assinatura** do CSR e de certificado autoassinado via Web
  Crypto (RSA PKCS#1 v1.5, RSA-PSS, ECDSA P-256/384/521, Ed25519). Detecta CSR
  corrompido na colagem.
- **Correspondencia de chaves**: colando CSR + certificado + .key juntos,
  compara o hash SHA-256 do SPKI de cada item e diz se usam a mesma chave
  (equivalente ao "certificate key matcher").
- **Cadeia**: colando certificado + AC emissora, valida a assinatura do
  emitido contra a chave da AC.
- **Descriptografia de chave** PKCS#8 PBES2 (PBKDF2 + AES-CBC) com senha,
  local. 3DES e PEM legado com DEK-Info nao sao suportados pelo navegador
  (a ferramenta indica o comando openssl para converter).
- **Tolerante a truncamento**: CSR colado pela metade (caso comum em ticket)
  ainda decodifica o Subject e avisa quantos bytes faltam.
- **OIDs ICP-Brasil**: otherNames 2.16.76.1.3.x (CPF, CNPJ, dados do titular
  e do responsavel, com mascara) e politicas 2.16.76.1.2.x (A1-A4).
- Avisos automaticos: chave < 2048 bits, assinatura SHA-1/MD5, CSR sem SAN,
  CN fora do SAN, certificado expirado ou a menos de 30 dias, alerta de
  manuseio ao colar chave privada.
- Fingerprints SHA-256/SHA-1 com botao copiar, arvore ASN.1 completa
  expansivel para investigacao, e o comando openssl equivalente em cada card.

## Como funciona (resumo tecnico)

PEM = cabecalho `-----BEGIN...-----` + DER codificado em base64. Base64 e
codificacao, nao criptografia. A pagina decodifica o base64 e percorre o DER
(TLV: tag, comprimento, valor) com um parser ASN.1 escrito em JavaScript puro,
sem bibliotecas externas. A interpretacao segue as estruturas das RFCs 2986
(PKCS#10), 5280 (X.509/CRL), 5208/5958 (PKCS#8) e 8018 (PBES2).



```
openssl req -in mycsr.csr -noout -text
```

## Validacao realizada (2026-07-17)


## Limitacoes conhecidas

- Descriptografia de chave: somente PBES2 com AES (navegador nao tem 3DES/MD5).
- Verificacao de assinatura MD5, DSA e curvas fora de P-256/384/521: apenas
  decodifica, nao verifica (limitacao do Web Crypto).
- CRLs muito grandes (varios MB) podem demorar alguns segundos.
