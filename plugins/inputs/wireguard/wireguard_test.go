package wireguard

var Output = `
interface: home
  public key: p3p3Uzj50FS7sdrTEviJwlsFaUu1TUdBsp+VZUdzm1I=
  private key: (hidden)
  listening port: 12345
  fwmark: 0xca6c

peer: JO2If0/wZ8ajoiUSU501u6uNtDZYSIYiz/xtazIMDi0=
  endpoint: 198.51.100.1:54321
  allowed ips: 192.168.2.0/24, 192.168.1.0/24
  latest handshake: 21 seconds ago
  transfer: 74.90 KiB received, 98.13 KiB sent

interface: remote
  public key: dwOgn4nnq8Zg23BOIolGSipNCKLz8Cf7aj2g3jPmX1E=
  private key: (hidden)
  listening port: 34567
  fwmark: 0xca6c

peer: WMwr/+0L4HJS4rsyM5oUlOUP+jTyp2HIuYPWfUNjC0c=
  endpoint: 203.0.113.100:443
  allowed ips: 0.0.0.0/0, ::/0
  latest handshake: 1 minute, 54 seconds ago
  transfer: 22.85 KiB received, 48.58 KiB sent
`
