# Backend remoto de estado — copiar a backend.staging.hcl (gitignored) y completar
# una vez creado el bucket S3 y la tabla DynamoDB de lock (fuera de este Terraform,
# para evitar el problema del huevo y la gallina de gestionar el propio backend).
#
# Uso: terraform init -backend-config=backend.staging.hcl

bucket         = "guardia-digital-tfstate-<sufijo-unico>"
key            = "staging/terraform.tfstate"
region         = "sa-east-1"
dynamodb_table = "guardia-digital-tfstate-lock"
encrypt        = true
