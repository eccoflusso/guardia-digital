# Backend remoto de estado — copiar a backend.staging.hcl (gitignored) y
# completar una vez creado el bucket GCS (fuera de este Terraform, para
# evitar el problema del huevo y la gallina de gestionar el propio backend).
#
# A diferencia de S3+DynamoDB, GCS no requiere una tabla de lock aparte: el
# locking de estado es nativo del backend "gcs" en Terraform >= 1.5.
#
# Uso: terraform init -backend-config=backend.staging.hcl

bucket = "guardia-digital-tfstate-ley20393"
prefix = "staging"
