"""Well-known package names used for typosquat / slopsquat distance checks."""

POPULAR_NPM = {
    "react", "react-dom", "lodash", "express", "axios", "next", "vue", "typescript", "webpack", "vite", "eslint",
    "prettier", "jest", "mocha", "chalk", "commander", "yargs", "dotenv", "moment", "dayjs", "uuid", "debug",
    "request", "node-fetch", "socket.io", "ws", "cors", "body-parser", "mongoose", "pg", "mysql2", "redis", "ioredis",
    "sequelize", "prisma", "knex", "passport", "jsonwebtoken", "bcrypt", "bcryptjs", "nodemon", "ts-node", "tsx",
    "rimraf", "glob", "minimist", "inquirer", "ora", "semver", "fs-extra", "mkdirp", "async", "bluebird", "rxjs",
    "underscore", "ramda", "immer", "zod", "yup", "joi", "ajv", "classnames", "tailwindcss", "postcss", "sass",
    "autoprefixer", "babel-core", "@babel/core", "esbuild", "rollup", "parcel", "svelte", "angular", "@angular/core",
    "nest", "@nestjs/core", "fastify", "koa", "hapi", "graphql", "apollo-server", "@apollo/client", "openai",
    "@anthropic-ai/sdk", "langchain", "@langchain/core", "llamaindex", "ollama", "@modelcontextprotocol/sdk",
    "puppeteer", "playwright", "cheerio", "jsdom", "sharp", "multer", "nodemailer", "stripe", "aws-sdk",
    "@aws-sdk/client-s3", "firebase", "firebase-admin", "supabase", "@supabase/supabase-js", "three", "d3",
    "chart.js", "electron", "pm2", "cross-env", "concurrently", "husky", "lint-staged", "shelljs", "execa",
    "got", "superagent", "form-data", "qs", "validator", "sanitize-html", "helmet", "compression", "morgan",
    "winston", "pino", "bunyan", "colors", "picocolors", "@types/node", "@types/react", "react-router-dom",
    "redux", "@reduxjs/toolkit", "zustand", "swr", "@tanstack/react-query", "styled-components", "emotion",
    "@mui/material", "antd", "bootstrap", "jquery", "ethers", "web3", "hardhat", "bun-types", "drizzle-orm",
}

POPULAR_PYPI = {
    "requests", "numpy", "pandas", "scipy", "matplotlib", "seaborn", "scikit-learn", "sklearn", "torch", "tensorflow",
    "keras", "transformers", "huggingface-hub", "huggingface_hub", "datasets", "tokenizers", "accelerate", "openai",
    "anthropic", "langchain", "langchain-core", "langchain-community", "langchain-openai", "llama-index", "llama_index",
    "litellm", "ollama", "mcp", "fastmcp", "chromadb", "qdrant-client", "pinecone-client", "pinecone", "weaviate-client",
    "faiss-cpu", "sentence-transformers", "tiktoken", "gradio", "streamlit", "flask", "django", "fastapi", "uvicorn",
    "gunicorn", "starlette", "pydantic", "pydantic-settings", "sqlalchemy", "alembic", "psycopg2", "psycopg2-binary",
    "psycopg", "pymysql", "mysqlclient", "redis", "celery", "boto3", "botocore", "google-cloud-storage",
    "google-api-python-client", "azure-storage-blob", "pyyaml", "toml", "tomli", "click", "typer", "rich", "tqdm",
    "colorama", "python-dotenv", "dotenv", "httpx", "aiohttp", "urllib3", "certifi", "idna", "charset-normalizer",
    "beautifulsoup4", "bs4", "lxml", "selenium", "playwright", "scrapy", "pillow", "opencv-python", "imageio",
    "pytest", "pytest-cov", "coverage", "tox", "nox", "black", "ruff", "flake8", "mypy", "isort", "pylint",
    "setuptools", "wheel", "pip", "poetry", "pipenv", "virtualenv", "cryptography", "pycryptodome", "paramiko",
    "fabric", "ansible", "docker", "kubernetes", "jinja2", "markupsafe", "werkzeug", "itsdangerous", "pyjwt",
    "python-jose", "passlib", "bcrypt", "jupyter", "jupyterlab", "notebook", "ipython", "ipykernel", "nbconvert",
    "protobuf", "grpcio", "pyarrow", "polars", "dask", "ray", "mlflow", "wandb", "xgboost", "lightgbm", "catboost",
    "statsmodels", "sympy", "networkx", "nltk", "spacy", "gensim", "psutil", "pexpect", "six", "attrs", "packaging",
    "python-dateutil", "pytz", "arrow", "pendulum", "orjson", "ujson", "simplejson", "msgpack", "websockets", "websocket-client",
    "pyserial", "paho-mqtt", "schedule", "apscheduler", "loguru", "structlog", "sentry-sdk", "twilio", "stripe",
}

# Names that were hallucinated by LLMs and later registered on a registry (documented cases).
KNOWN_SLOPSQUATS = {
    "npm": set(),
    "pypi": {"huggingface-cli", "openai-python", "langchain-utils", "pytorch-cuda", "fastapi-utils-auth"},
}
