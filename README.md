# sable-escritorio
Sable personalizado do escritório

## Ensaios de teste (sem publicação de produto)

`experiments/` guarda ensaios de teste; nenhum workflow daqui publica release do Sable,
ativa atualização ou toca produção. `experiments/sable-real-windows` roda o Sable genuíno
2.2.2 -> 2.2.3 num runner Windows descartável (`sable-real-windows.yml`, só manual).
A fonte privada não é commitada: entra cifrada (SABLE-TI v1, AES-256-GCM) como asset de
prerelease de teste, decifrada só no passo com o secret `SABLE_TEST_INPUT_KEY` e apagada
no fim. O artifact contém somente a allowlist pública do driver (até 25 MiB).
`sable-real-check.yml` roda só UNIT puro em PR/push; PASS Native exige o resultado do driver.
