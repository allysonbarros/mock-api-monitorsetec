# Use a imagem oficial do Python 3.8 como base
FROM python:3-slim

# Define o diretório de trabalho dentro do contêiner
WORKDIR /app

# Copia o arquivo de requisitos e instala as dependências
COPY requirements.txt .

# Instala as dependências
RUN pip install -r requirements.txt

# Copia o código do aplicativo para o contêiner
COPY . .

# Expõe a porta 80
EXPOSE 80

# Comando para iniciar o aplicativo
CMD ["uvicorn", "main:app", "--reload", "--host", "0.0.0.0", "--port", "80"]
