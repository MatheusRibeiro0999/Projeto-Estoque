import sqlite3
import bcrypt
import getpass
from datetime import datetime
#databases
class DatabaseManager:

#função pra inicializar as databases
    def __init__(self, db_name='usuarios.db'):
        self.db_name = db_name
        self.open_connection()
        self.criar_tabela()
        self.verificar_usuario_admin()

#função pra iniciar a conexão com o banco
    def open_connection(self):
        self.connection = sqlite3.connect(self.db_name)
        self.cursor = self.connection.cursor()

#função pra encerrar a conexão com o banco
    def close_connection(self):
        self.connection.commit()
        self.connection.close()
#cria as databases
    def criar_tabela(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                login TEXT,
                senha TEXT,
                admin INTEGER
            )
        ''')
    
        self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS estoque (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    produto TEXT,
                    quantidade INTEGER
                )
            ''')

        self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    usuario TEXT,
                    horario TEXT,
                    acao TEXT,
                    produto TEXT,
                    quantidade INTEGER
                    
                )
            ''')

#verifica se já existe admin ao executar o código pela primeira vez
    def verificar_usuario_admin(self):
        self.cursor.execute('SELECT * FROM usuarios WHERE admin = 1')
        admin_existente = self.cursor.fetchone()

        #se o admin não existe, cria o login admin com a senha admin por default
        if not admin_existente:
            login_admin = 'admin'
            senha_admin = 'admin'  # Senha padrão
            hashed_senha = bcrypt.hashpw(senha_admin.encode('utf-8'), bcrypt.gensalt())
            self.cursor.execute('INSERT INTO usuarios (login, senha, admin) VALUES (?, ?, 1)', (login_admin, hashed_senha.decode('utf-8')))
            print("Usuário administrador criado.")
            self.close_connection()

#função pra fazer login/inicio da aplicação
    def fazer_login(self):
        while True:
            login = input("Digite o nome de usuário: ")
            senha = getpass.getpass("Digite a senha: ")
            
            self.open_connection()
            self.cursor.execute('SELECT * FROM usuarios WHERE login = ?', (login,))
            usuario = self.cursor.fetchone()

            if usuario and bcrypt.checkpw(senha.encode('utf-8'), usuario[2].encode('utf-8')):
                print("Login bem-sucedido!")

                self.registrar_log_acesso(login)

                if usuario[3] == 1:  # Verifica se é um administrador
                    if senha == 'admin':
                        print("Por favor, altere sua senha padrão.")
                        self.alterar_senha(login)
                    else:
                        self.menu_administracao()
                return main()
            else:
                print("Login ou senha incorretos. Tente novamente.")

#função pra registrar os logs de acesso e salvar na tabela log
    def registrar_log_acesso(self, usuario):
        # Obtém a data e hora atual
        horario_acesso = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        self.open_connection()
  
        self.cursor.execute('INSERT INTO logs (usuario, horario, acao) VALUES (?, ?, ?)', (usuario, horario_acesso, 'Login'))
        print("Log de acesso registrado com sucesso.")

        
        self.connection.commit()
        self.close_connection()

#função pra definir o menu de administração, com todos as opções
    def menu_administracao(self):
        while True:
            print("\nMenu de Administração:")
            print("1 - Adicionar Usuário")
            print("2 - Remover Usuário")
            print("3 - Alterar Senha")
            print("4 - Consultar Banco de Dados")
            print("5 - Consultar Log de Acesso")
            print("6 - Consultar Estoque")
            print("7 - Atualizar Quantidade de Produtos")
            print("8 - Registrar Entrada de Produtos")
            print("9 - Registrar Saída de Produtos")
            print("10 - Consultar Produtos de Baixo Estoque")
            print("11 - Consultar Movimentações do Estoque")
            print("12 - Gerar Relatórios de Estoque")
            print("13 - Gerenciar Fornecedores")
            print("14 - Gerenciar Categorias de Produtos")
            print("EXIT - Sair")
            
            opcao = input("Escolha uma opção: ")

            opcao = opcao.upper()

            if opcao == '1':
                self.adicionar_usuario()
            elif opcao == '2':
                self.remover_usuario()
            elif opcao == '3':
                self.alterar_senha()
            elif opcao == '4':
                self.consultar_banco_dados()
            elif opcao == '5':
                self.consultar_log_acesso()
            elif opcao == '6':
                self.consultar_estoque()
            elif opcao == '7':
                self.atualizar_quantidade_produto()
            elif opcao == '8':
                self.registrar_entrada_produto()
            elif opcao == '9':
                self.registrar_saida_produto()
            elif opcao == '10':
                self.consultar_produtos_baixo_estoque()
            elif opcao == '11':
                self.consultar_movimentacoes_estoque()
            elif opcao == '12':
                self.gerar_relatorios_estoque()
            elif opcao == '13':
                self.gerenciar_fornecedores()
            elif opcao == '14':
                self.gerenciar_categorias_produtos()
            elif opcao == 'EXIT':
                print("Saindo do menu de administração.")
                return main()
            else:
                print("Opção inválida. Tente novamente.")

## função pra adicionar usuário e senha na tabela usuario
    def adicionar_usuario(self):
        while True:
            novo_usuario = input("Digite o nome do novo usuário: ")
            nova_senha = getpass.getpass("Digite a senha do novo usuário: ")

            if len(novo_usuario) >= 3 and len(nova_senha) >= 3:
                hashed_senha = bcrypt.hashpw(nova_senha.encode('utf-8'), bcrypt.gensalt())

                self.open_connection()
                self.cursor.execute('INSERT INTO usuarios (login, senha, admin) VALUES (?, ?, 0)', (novo_usuario, hashed_senha.decode('utf-8')))
                print("Novo usuário cadastrado com sucesso!")
                self.close_connection()
                break
            else:
                print("Nome e senha do usuário devem ter no mínimo 3 caracteres. Tente novamente.")

##função pra remover usuário da tabela
    def remover_usuario(self):
        usuario_para_remover = input("Digite o nome do usuário a ser removido: ")

        self.open_connection()
        self.cursor.execute('SELECT * FROM usuarios WHERE login = ?', (usuario_para_remover,))
        usuario = self.cursor.fetchone()

        if usuario:
            self.cursor.execute('DELETE FROM usuarios WHERE login = ?', (usuario_para_remover,))
            print(f"Usuário '{usuario_para_remover}' removido com sucesso!")
        else:
            print(f"Usuário '{usuario_para_remover}' não encontrado.")

        self.close_connection()

#função pra alterar a senha do usuário/pesquisa pelo nome de usuário na tabela
    def alterar_senha(self, usuario=None):
        if not usuario:
            usuario = input("Digite o nome de usuário para alterar a senha: ")

        self.open_connection()
        self.cursor.execute('SELECT * FROM usuarios WHERE login = ?', (usuario,))
        usuario = self.cursor.fetchone()

        if usuario:
            nova_senha = getpass.getpass("Digite a nova senha: ")

            if len(nova_senha) >= 3:
                hashed_senha = bcrypt.hashpw(nova_senha.encode('utf-8'), bcrypt.gensalt())
                self.cursor.execute('UPDATE usuarios SET senha = ? WHERE login = ?', (hashed_senha.decode('utf-8'), usuario[1]))
                print(f"Senha do usuário '{usuario[1]}' alterada com sucesso!")
            else:
                print("A nova senha deve ter no mínimo 3 caracteres. Tente novamente.")
        else:
            print(f"Usuário '{usuario}' não encontrado.")

        self.close_connection()

#função pra retornar os dados na tabela usuarios
    def consultar_banco_dados(self):
        self.open_connection()
        self.cursor.execute('SELECT * FROM usuarios')
        usuarios = self.cursor.fetchall()

        print("\nConsulta ao Banco de Dados:")
        for usuario in usuarios:
            print(f"ID: {usuario[0]}, Login: {usuario[1]}, Admin: {usuario[3]}")

        self.close_connection()

#função pra consultar tabela de logs de acesso
    def consultar_log_acesso(self):
        self.open_connection()
        self.cursor.execute('SELECT * FROM logs')
        logs = self.cursor.fetchall()

        print("\nLog de Acesso: ")
        for log in logs:
            print(f"ID: {log[0]}, Usuário: {log[1]}, Horário: {log[2]}")

        self.close_connection()

#função pra consultar estoque na tabela estoque
    def consultar_estoque(self):
        self.open_connection()
        self.cursor.execute('SELECT produto, quantidade FROM estoque')
        estoque = self.cursor.fetchall()

        print("\nConsulta de Estoque:")
        for produto in estoque:
            print(f"produto: {produto[0]}, quantidade: {produto[1]}")

        self.close_connection()

#função pra atualizar a quantidade de determinado produto
    def atualizar_quantidade_produto(self):
        produto = input("Digite o nome do produto que deseja atualizar: ")
        nova_quantidade = int(input("Digite a nova quantidade: "))

        self.open_connection()
        self.cursor.execute('UPDATE estoque SET quantidade = ? WHERE produto = ?', (nova_quantidade, produto))
        self.connection.commit()
        print(f"Quantidade do produto '{produto}' atualizada com sucesso para {nova_quantidade}.")
        self.close_connection()

#função pra registrar entrada de produto no estoque
    def registrar_entrada_produto(self):
        produto = input("Digite o nome do produto a ser registrado: ")
        quantidade = int(input("Digite a quantidade do produto a ser adicionada: "))

        self.open_connection()

        self.cursor.execute('SELECT * FROM estoque WHERE produto = ?', (produto,))
        produto_existente = self.cursor.fetchone()

        if produto_existente:
            nova_quantidade = produto_existente[2] + quantidade
            self.cursor.execute('UPDATE estoque SET quantidade = ? WHERE produto = ?', (nova_quantidade, produto))
            print(f"Quantidade do produto '{produto}' atualizada com sucesso para {nova_quantidade}.")
        
        else:
            
            self.cursor.execute('INSERT INTO estoque (produto, quantidade) VALUES (?, ?)', (produto, quantidade))
            print(f"Produto '{produto}' registrado com sucesso com quantidade {quantidade}.")

        self.connection.commit()
        self.close_connection()

#função pra retirar produto da tabela estoque
    def registrar_saida_produto(self):

        produto = input("Digite o nome do produto que deseja registrar a saída: ")
        quantidade = int(input("Digite a quantidade a ser retirada do estoque: "))

        horario_saida = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        self.open_connection()

        self.cursor.execute('SELECT * FROM estoque WHERE produto = ?', (produto,))
        produto_estoque = self.cursor.fetchone()

        if produto_estoque:
            if produto_estoque[2] >= quantidade:
                nova_quantidade = produto_estoque[2] - quantidade
                self.cursor.execute('UPDATE estoque SET quantidade = ? WHERE produto = ?', (nova_quantidade, produto))

                self.cursor.execute('INSERT INTO logs (produto, quantidade, horario, acao) VALUES (?, ?, ?, ?)',
                                    (produto, quantidade, horario_saida, 'Saída'))
                print(f"Saída de {quantidade} unidades de '{produto}' registrada com sucesso.")
            else:
                print("Quantidade insuficiente em estoque.")
        else:
            print("Produto não encontrado no estoque.")

        self.connection.commit()
        self.close_connection()

#função pra definir e informar produtos com estoque baixo TESTANDO, PRECISA SEPARAR O ESTOQUE POR PRODUTO
    def consultar_produtos_baixo_estoque(self, limite=100): ##limite minimo 100
        self.open_connection()
        
        # Consulta os produtos com quantidade menor do que o limite especificado
        self.cursor.execute('SELECT produto, quantidade FROM estoque WHERE quantidade < ?', (limite,))
        produtos_baixo_estoque = self.cursor.fetchall()

        # Verifica se há produtos com baixo estoque
        if produtos_baixo_estoque:
            print("\nProdutos com Baixo Estoque:")
            for produto in produtos_baixo_estoque:
                print(f"Produto: {produto[0]}, Quantidade: {produto[1]}")
        else:
            print("Não há produtos com baixo estoque.")

        self.close_connection()
        
#função pra consultar movimentações no estoque (NÃO FIZ AINDA)
    def consultar_movimentacoes_estoque(self):
        pass
# função pra gerar relatórios do estoque NÃO FIZ AINDA
    def gerar_relatorios_estoque(self):
        pass
#função pra gerenciar lista de fornecedores NÃO FIZ AINDA
    def gerenciar_fornecedores(self):
        pass
#funão pra categorizar produtos NÃO FIZ AINDA
    def gerenciar_categorias_produtos(self):
        pass

## Main pra retornar ao inicio
def main():

    db_manager = DatabaseManager()
    db_manager.fazer_login()

if __name__ == "__main__":
    main()
