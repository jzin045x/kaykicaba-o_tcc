import express, { type Request, type Response } from 'express';
import dotenv from 'dotenv';
import { pool } from './config/database.js';
import cors from 'cors';
import crypto from 'crypto';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// ---------------------------------------------------------------------------
// Segredo usado para assinar os tokens. Se quiser, defina JWT_SECRET no Render.
// ---------------------------------------------------------------------------
const SEGREDO = process.env.JWT_SECRET || 'escola-chato-hype-2026';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function falhar(res: Response, status: number, mensagem: string) {
  return res.status(status).json({ error: mensagem });
}

function gerarToken(dados: Record<string, unknown>): string {
  const corpo = Buffer.from(JSON.stringify({ ...dados, iat: Date.now() })).toString('base64url');
  const assinatura = crypto.createHmac('sha256', SEGREDO).update(corpo).digest('base64url');
  return `${corpo}.${assinatura}`;
}

function lerToken(valor: string | undefined): Record<string, any> | null {
  if (!valor) return null;
  const bruto = String(valor).replace(/^Bearer\s+/i, '');
  const [corpo, assinatura] = bruto.split('.');
  if (!corpo || !assinatura) return null;
  const esperada = crypto.createHmac('sha256', SEGREDO).update(corpo).digest('base64url');
  if (assinatura.length !== esperada.length || assinatura !== esperada) return null;
  try {
    return JSON.parse(Buffer.from(corpo, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

function hashSenha(senha: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(senha, salt, 64).toString('hex');
  return `scrypt$${salt}$${hash}`;
}

// Aceita senhas antigas em texto puro e senhas novas em hash scrypt.
function senhaConfere(senha: string, salva: unknown): boolean {
  if (typeof salva !== 'string' || !salva) return false;
  if (salva.startsWith('scrypt$')) {
    const partes = salva.split('$');
    if (partes.length !== 3) return false;
    const calculado = crypto.scryptSync(senha, partes[1], 64).toString('hex');
    return calculado === partes[2];
  }
  return senha === salva;
}

async function colunasDaTabela(tabela: string): Promise<Set<string>> {
  const [linhas]: any = await pool.query(
    'SELECT COLUMN_NAME AS nome FROM information_schema.COLUMNS ' +
      'WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?',
    [tabela]
  );
  return new Set(linhas.map((l: any) => l.nome));
}

async function tabelasExistentes(): Promise<Set<string>> {
  const [linhas]: any = await pool.query(
    'SELECT TABLE_NAME AS nome FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()'
  );
  return new Set(linhas.map((l: any) => l.nome));
}

function colEscolhida(colunas: Set<string>, candidatas: string[]): string | null {
  for (const c of candidatas) if (colunas.has(c)) return c;
  return null;
}

function usuarioPublico(linha: any) {
  return {
    nome: linha['NOME COMPLETO'] ?? linha.NOME ?? null,
    cpf: linha.CPF ?? null,
    email: linha.EMAIL ?? linha.email ?? null,
    telefone: linha.TELEFONE ?? null,
    tipo: linha.TIPO ?? 'cliente',
  };
}

// ---------------------------------------------------------------------------
// HEALTH
// ---------------------------------------------------------------------------
app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, servico: 'escola-chato-api', hora: new Date().toISOString() });
  } catch (error: any) {
    falhar(res, 500, 'Banco de dados indisponível: ' + error.message);
  }
});

app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, servico: 'escola-chato-api', hora: new Date().toISOString() });
  } catch (error: any) {
    falhar(res, 500, 'Banco de dados indisponível: ' + error.message);
  }
});

// ---------------------------------------------------------------------------
// LOGIN  (/api/login e /login — a rota antiga continua funcionando)
// ---------------------------------------------------------------------------
async function fazerLogin(req: Request, res: Response) {
  const { email, senha } = req.body ?? {};
  if (!email || !senha) return falhar(res, 400, 'E-mail e senha são obrigatórios.');

  try {
    const colunas = await colunasDaTabela('cadastro');
    const campos = ['`NOME COMPLETO`', '`CPF`', '`EMAIL`', '`TELEFONE`', '`SENHA`'];
    if (colunas.has('TIPO')) campos.push('`TIPO`');

    const [linhas]: any = await pool.query(
      `SELECT ${campos.join(', ')} FROM \`cadastro\` WHERE \`EMAIL\` = ? LIMIT 1`,
      [email]
    );

    if (!linhas || linhas.length === 0) {
      return falhar(res, 401, 'E-mail ou senha incorretos.');
    }

    const usuario = linhas[0];
    if (!senhaConfere(String(senha), usuario.SENHA)) {
      return falhar(res, 401, 'E-mail ou senha incorretos.');
    }

    const publico = usuarioPublico(usuario);
    const token = gerarToken({
      cpf: publico.cpf,
      email: publico.email,
      nome: publico.nome,
      tipo: publico.tipo,
    });

    return res.status(200).json({
      mensagem: 'Login realizado com sucesso!',
      token,
      usuario: publico,
    });
  } catch (error: any) {
    console.error('Erro no login:', error);
    return falhar(res, 500, 'Erro no servidor ao tentar logar.');
  }
}

app.post('/api/login', fazerLogin);
app.post('/login', fazerLogin);

// ---------------------------------------------------------------------------
// CRIAR CONTA  (/api/cadastro, /api/usuarios e /usuarios)
// ---------------------------------------------------------------------------
async function criarConta(req: Request, res: Response) {
  const { nome, email, senha, telefone, cpf, tipo, recuperacao } = req.body ?? {};

  if (!nome || !email || !senha) {
    return falhar(res, 400, 'Nome, e-mail e senha são obrigatórios.');
  }
  if (!/^\S+@\S+\.\S+$/.test(String(email))) {
    return falhar(res, 400, 'E-mail inválido.');
  }
  if (String(senha).length < 4) {
    return falhar(res, 400, 'A senha deve ter ao menos 4 caracteres.');
  }

  try {
    const colunas = await colunasDaTabela('cadastro');

    const [existe]: any = await pool.query(
      'SELECT `EMAIL` FROM `cadastro` WHERE `EMAIL` = ? LIMIT 1',
      [email]
    );
    if (existe.length > 0) return falhar(res, 409, 'Este e-mail já está cadastrado.');

    if (cpf) {
      const [cpfExiste]: any = await pool.query(
        'SELECT `CPF` FROM `cadastro` WHERE `CPF` = ? LIMIT 1',
        [cpf]
      );
      if (cpfExiste.length > 0) return falhar(res, 409, 'Este CPF já está cadastrado.');
    }

    const campos = ['`NOME COMPLETO`', '`EMAIL`', '`SENHA`'];
    const valores: any[] = [nome, email, hashSenha(String(senha))];
    if (colunas.has('CPF')) {
      campos.push('`CPF`');
      valores.push(cpf || null);
    }
    if (colunas.has('TELEFONE')) {
      campos.push('`TELEFONE`');
      valores.push(telefone || '');
    }
    if (colunas.has('TIPO')) {
      campos.push('`TIPO`');
      valores.push(tipo || 'cliente');
    }

    const sql = `INSERT INTO \`cadastro\` (${campos.join(', ')}) VALUES (${campos.map(() => '?').join(', ')})`;
    const [result]: any = await pool.query(sql, valores);

    // A tabela `login` é espelho antiga. Se falhar, o cadastro principal já foi salvo.
    try {
      const colunasLogin = await colunasDaTabela('login');
      const camposLogin = ['`EMAIL`', '`SENHA`'];
      const valoresLogin: any[] = [email, hashSenha(String(senha))];
      const colRecuperacao = colEscolhida(colunasLogin, [
        'EMAIL DE RECUPERAÇÃO DE CONTA',
        'EMAIL DE RECUPERAÇÃO DE CONTA',
      ]);
      if (colRecuperacao) {
        camposLogin.push(`\`${colRecuperacao.replace(/`/g, '``')}\``);
        valoresLogin.push(recuperacao || email);
      }
      await pool.query(
        `INSERT INTO \`login\` (${camposLogin.join(', ')}) VALUES (${camposLogin.map(() => '?').join(', ')})`,
        valoresLogin
      );
    } catch (erroLogin: any) {
      console.warn('Aviso: linha espelho em `login` não gravada:', erroLogin.message);
    }

    const token = gerarToken({
      cpf: cpf || null,
      email,
      nome,
      tipo: tipo || 'cliente',
    });

    return res.status(201).json({
      mensagem: 'Conta criada com sucesso!',
      token,
      usuario: { nome, email, cpf: cpf || null, telefone: telefone || '', tipo: tipo || 'cliente' },
      id: result.insertId || null,
    });
  } catch (error: any) {
    console.error('Erro ao criar conta:', error);
    return falhar(res, 500, 'Erro interno ao salvar o usuário.');
  }
}

app.post('/api/cadastro', criarConta);
app.post('/api/usuarios', criarConta);
app.post('/usuarios', criarConta);

// ---------------------------------------------------------------------------
// PRODUTOS
// ---------------------------------------------------------------------------
function selectProdutos(colunas: Set<string>): string {
  const pares: Array<[string, string]> = [
    ['`CodigoProduto`', 'id'],
    ['`Nome Do Produto`', 'nome'],
    ['`Modelo Do Produto`', 'modelo'],
    ['`Marca Do Produto`', 'marca'],
    ['`Local Do Produto`', 'local'],
    ['`Estoque Do Produto`', 'estoque'],
    ['`Promoções Do Produto`', 'promocao'],
    ['`Descontos Do Produto`', 'desconto'],
    [colunas.has('PRECO') ? '`PRECO`' : '0', 'preco'],
    [colunas.has('IMAGEM') ? '`IMAGEM`' : "''", 'imagem'],
    [colunas.has('CATEGORIA') ? '`CATEGORIA`' : "''", 'categoria'],
    [colunas.has('ATIVO') ? '`ATIVO`' : '1', 'ativo'],
  ];
  return pares.map(([col, alias]) => `${col} AS \`${alias}\``).join(', ');
}

app.get('/api/produtos', async (_req, res) => {
  try {
    const colunas = await colunasDaTabela('produtos-hypestyle');
    const [linhas]: any = await pool.query(
      `SELECT ${selectProdutos(colunas)} FROM \`produtos-hypestyle\` ORDER BY \`CodigoProduto\` DESC`
    );
    res.json(linhas);
  } catch (error: any) {
    console.error('Erro ao buscar produtos:', error);
    falhar(res, 500, 'Erro ao buscar os produtos.');
  }
});

app.get('/api/produtos/:id', async (req, res) => {
  try {
    const colunas = await colunasDaTabela('produtos-hypestyle');
    const [linhas]: any = await pool.query(
      `SELECT ${selectProdutos(colunas)} FROM \`produtos-hypestyle\` WHERE \`CodigoProduto\` = ? LIMIT 1`,
      [req.params.id]
    );
    if (linhas.length === 0) return falhar(res, 404, 'Produto não encontrado.');
    res.json(linhas[0]);
  } catch (error: any) {
    console.error('Erro ao buscar produto:', error);
    falhar(res, 500, 'Erro ao buscar o produto.');
  }
});

// Rota antiga preservada
app.get('/produtos', async (_req, res) => {
  try {
    const [tabelas]: any = await pool.query("SHOW TABLES LIKE 'produtos-hypestyle'");
    if (tabelas.length === 0) return res.json([]);
    const [linhas]: any = await pool.query('SELECT * FROM `produtos-hypestyle` ORDER BY `CodigoProduto` DESC');
    res.json(linhas);
  } catch (error: any) {
    console.error('Erro ao buscar produtos:', error);
    falhar(res, 500, 'Erro ao buscar os produtos.');
  }
});

// Rota antiga preservada
app.post('/produtos', async (req, res) => {
  const { nome, preco } = req.body ?? {};
  if (!nome || !preco) return falhar(res, 400, 'Nome e preço são obrigatórios.');
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS \`produtos-vini\` (
        id INT AUTO_INCREMENT PRIMARY KEY,
        nome VARCHAR(255) NOT NULL,
        preco DECIMAL(10, 2) NOT NULL,
        criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await pool.query('INSERT INTO `produtos-vini` (nome, preco) VALUES (?, ?)', [nome, preco]);
    res.status(201).json({ mensagem: 'Produto inserido com sucesso!' });
  } catch (error: any) {
    console.error('Erro ao inserir produto:', error);
    falhar(res, 500, 'Erro interno ao salvar o produto.');
  }
});

// ---------------------------------------------------------------------------
// PEDIDOS
// ---------------------------------------------------------------------------
app.post('/api/pedidos', async (req, res) => {
  const body = req.body ?? {};
  const itens: any[] = Array.isArray(body.itens) ? body.itens : [];

  if (itens.length === 0) return falhar(res, 400, 'O pedido precisa ter ao menos um item.');

  const email = body.email || body.email_cliente || null;
  let cpf = body.cpf || null;

  try {
    const colunas = await colunasDaTabela('pedidos de produto');
    const tabelas = await tabelasExistentes();

    let nomeCliente: string | null = body.nome || body.nome_cliente || null;
    let codigoCliente: number | null = body.codigo_cliente ?? null;

    if (email || cpf) {
      const colunasCadastro = await colunasDaTabela('cadastro');
      const where = email && colunasCadastro.has('EMAIL') ? '`EMAIL` = ?' : '`CPF` = ?';
      const [clientes]: any = await pool.query(
        `SELECT \`NOME COMPLETO\`, \`CPF\` FROM \`cadastro\` WHERE ${where} LIMIT 1`,
        [email || cpf]
      );
      if (clientes.length > 0) {
        nomeCliente = nomeCliente || clientes[0]['NOME COMPLETO'];
        if (colunasCadastro.has('CPF')) cpf = cpf || clientes[0].CPF;
      }
      const colunasCliente = await colunasDaTabela('cliente');
      const colCodigo = colEscolhida(colunasCliente, ['CODIGO CLIENTE']);
      if (colCodigo && (email || cpf)) {
        const colEmail = colunasCliente.has('EMAIL') ? '`EMAIL`' : null;
        const colCpf = colunasCliente.has('CPF') ? '`CPF`' : null;
        if (colEmail && email) {
          const [cli]: any = await pool.query(
            `SELECT \`${colCodigo.replace(/`/g, '``')}\` AS codigo FROM \`cliente\` WHERE ${colEmail} = ? LIMIT 1`,
            [email]
          );
          if (cli.length > 0) codigoCliente = cli[0].codigo;
        }
      }
    }

    const itensNormalizados = itens.map((item: any) => {
      const precoUnitario = Number(item.preco ?? item.price ?? 0) || 0;
      const quantidade = Math.max(1, Number(item.quantidade ?? item.quantity ?? 1) || 1);
      return {
        id: item.id ?? item.product_id ?? null,
        nome: String(item.nome ?? item.name ?? ''),
        preco: precoUnitario,
        quantidade,
        subtotal: precoUnitario * quantidade,
      };
    });

    const totalCalculado = itensNormalizados.reduce((soma: number, i: any) => soma + i.subtotal, 0);
    const total = body.total !== undefined && body.total !== null && body.total !== ''
      ? Number(body.total) || 0
      : totalCalculado;

    const campos: string[] = [];
    const valores: any[] = [];
    const add = (coluna: string, valor: any) => {
      if (colunas.has(coluna)) {
        campos.push(`\`${coluna.replace(/`/g, '``')}\``);
        valores.push(valor);
      }
    };

    add('Local De Entrada', body.local_entrada ?? 'Site');
    add('Local De Saida', body.local_saida ?? 'Site');
    add('Entrega', body.entrega ?? '');
    add('Retirada', body.retirada ?? '');
    add('Correios', body.correios ?? '');
    add('Pedido Pronto Pra Retirar', 'pendente');
    add('Entregue', 'nao');
    add('Avaliações', '');
    add('CODIGO_CLIENTE', codigoCliente);
    add('EMAIL_CLIENTE', email);
    add('NOME_CLIENTE', nomeCliente);
    add('TOTAL', total);
    add('STATUS', body.status || 'pendente');
    add('DATA_PEDIDO', new Date());
    add('OBSERVACAO', body.observacao ?? JSON.stringify(itensNormalizados));

    if (campos.length === 0) return falhar(res, 500, 'A tabela de pedidos não tem colunas graváveis.');

    const sql = `INSERT INTO \`pedidos de produto\` (${campos.join(', ')}) VALUES (${campos.map(() => '?').join(', ')})`;
    const [result]: any = await pool.query(sql, valores);

    let idPedido: any = result.insertId;
    if (!idPedido && colunas.has('ID_PEDIDO')) {
      const [max]: any = await pool.query('SELECT MAX(`ID_PEDIDO`) AS id FROM `pedidos de produto`');
      idPedido = max[0]?.id ?? null;
    }

    if (tabelas.has('pedido_itens')) {
      for (const item of itensNormalizados) {
        await pool.query(
          'INSERT INTO `pedido_itens` (`ID_PEDIDO`, `CODIGO_PRODUTO`, `NOME_PRODUTO`, `PRECO_UNITARIO`, `QUANTIDADE`, `SUBTOTAL`) VALUES (?, ?, ?, ?, ?, ?)',
          [idPedido, item.id, item.nome, item.preco, item.quantidade, item.subtotal]
        );
      }
    }

    return res.status(201).json({
      mensagem: 'Pedido realizado com sucesso!',
      pedido: {
        id: idPedido,
        email,
        nome_cliente: nomeCliente,
        total,
        status: body.status || 'pendente',
        itens: itensNormalizados,
      },
    });
  } catch (error: any) {
    console.error('Erro ao criar pedido:', error);
    return falhar(res, 500, 'Erro ao salvar o pedido: ' + error.message);
  }
});

app.get('/api/pedidos', async (req, res) => {
  try {
    const colunas = await colunasDaTabela('pedidos de produto');
    const dados = lerToken(req.headers.authorization);
    const emailFiltro = (req.query.email as string) || dados?.email || null;

    const where = emailFiltro && colunas.has('EMAIL_CLIENTE') ? 'WHERE `EMAIL_CLIENTE` = ?' : '';
    const ordem = colunas.has('ID_PEDIDO') ? 'ORDER BY `ID_PEDIDO` DESC' : '';
    const params = emailFiltro && colunas.has('EMAIL_CLIENTE') ? [emailFiltro] : [];

    const [linhas]: any = await pool.query(
      `SELECT * FROM \`pedidos de produto\` ${where} ${ordem} LIMIT 100`,
      params
    );
    res.json(linhas);
  } catch (error: any) {
    console.error('Erro ao listar pedidos:', error);
    falhar(res, 500, 'Erro ao listar os pedidos.');
  }
});

app.get('/api/pedidos/:id', async (req, res) => {
  try {
    const colunas = await colunasDaTabela('pedidos de produto');
    if (!colunas.has('ID_PEDIDO')) return falhar(res, 404, 'Pedido não encontrado.');

    const [linhas]: any = await pool.query(
      'SELECT * FROM `pedidos de produto` WHERE `ID_PEDIDO` = ? LIMIT 1',
      [req.params.id]
    );
    if (linhas.length === 0) return falhar(res, 404, 'Pedido não encontrado.');

    const tabelas = await tabelasExistentes();
    let itens: any[] = [];
    if (tabelas.has('pedido_itens')) {
      const [rows]: any = await pool.query('SELECT * FROM `pedido_itens` WHERE `ID_PEDIDO` = ?', [req.params.id]);
      itens = rows;
    }
    res.json({ ...linhas[0], itens });
  } catch (error: any) {
    console.error('Erro ao buscar pedido:', error);
    falhar(res, 500, 'Erro ao buscar o pedido.');
  }
});

// ---------------------------------------------------------------------------
// Rota antiga preservada
// ---------------------------------------------------------------------------
app.get('/descobrir-tabelas', async (_req, res) => {
  try {
    const [linhas]: any = await pool.query('SHOW TABLES');
    const tabelas = linhas.map((linha: any) => Object.values(linha)[0]);
    res.json({ tabelas });
  } catch (error) {
    falhar(res, 500, 'Erro');
  }
});

// ---------------------------------------------------------------------------
// Subida do servidor
// ---------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT} 🚀`);

  pool.getConnection()
    .then((connection) => {
      console.log('✅ SUCESSO: O Node.js conseguiu conectar no banco MySQL!');
      connection.release();
    })
    .catch((error) => {
      console.log('\n❌ ERRO CRÍTICO NO BANCO DE DADOS:');
      console.log(error.message);
      console.log('Verifique a senha, o usuário ou se o servidor robb0253.publiccloud.com.br está bloqueando conexões externas.\n');
    });
});
