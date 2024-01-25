import sqlite3
import bcrypt
import getpass

class DatabaseManager:
    def __init__(self, db_name='usuarios.db'):
        self.db_name = db_name
        self.open_connection()
        self.criar_tabela()
        self.criar_tabela_logs()

    def open_connection(self):
        self.connection = sqlite3.connect(self.db_name)
        self.cursor = self.connection.cursor()

    def close_connection(self):
        self.connection.commit()
        self.connection.close()

    def criar_tabela(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                login TEXT,
                senha TEXT,
                admin INTEGER
            )
        ''')

    def criar_tabela_logs(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario TEXT,
                horario TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

    def cadastrar_administrador(self):
        # Verifica se já tem adm
        self.cursor.execute('SELECT * FROM usuarios WHERE admin = 1')
        admin_existente = self.cursor.fetchone()

        if admin_existente:
            print("Já existe um administrador cadastrado.")
            return

        while True:
            login = input("Digite o nome do administrador: ")
            senha = getpass.getpass("Digite a senha do administrador: ")

            if len(login) >= 3 and len(senha) >= 3:
                hashed_senha = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt())

                # Insere o adm no banco
                self.cursor.execute('INSERT INTO usuarios (login, senha, admin) VALUES (?, ?, 1)', (login, hashed_senha.decode('utf-8')))
                print("Administrador cadastrado com sucesso!")
                break
            else:
                print("Nome e senha do administrador devem ter no mínimo 3 caracteres. Tente novamente.")

    def fazer_login(self):
        while True:
            login = input("Digite o nome de usuário: ")
            senha = getpass.getpass("Digite a senha: ")

            # Verifica se o login existe
            self.cursor.execute('SELECT * FROM usuarios WHERE login = ?', (login,))
            usuario = self.cursor.fetchone()

            if usuario and bcrypt.checkpw(senha.encode('utf-8'), usuario[2].encode('utf-8')):
                print("Login bem-sucedido!")
                self.registrar_log_acesso(login)

                if usuario[3] == 1:  # Verifica se é um administrador
                    self.menu_administracao()
                break
            else:
                print("Login ou senha incorretos. Tente novamente.")

    def menu_administracao(self):
        while True:
            print("\nMenu de Administração:")
            print("1 - Adicionar Usuário")
            print("2 - Remover Usuário")
            print("3 - Alterar Senha")
            print("4 - Consultar Banco de Dados")
            print("5 - Consultar Log de Acesso")
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
            elif opcao == 'EXIT':
                print("Saindo do menu de administração.")
                break
            else:
                print("Opção inválida. Tente novamente.")

    def adicionar_usuario(self):
        while True:
            novo_usuario = input("Digite o nome do novo usuário: ")
            nova_senha = getpass.getpass("Digite a senha do novo usuário: ")

            if len(novo_usuario) >= 3 and len(nova_senha) >= 3:
                hashed_senha = bcrypt.hashpw(nova_senha.encode('utf-8'), bcrypt.gensalt())

                # Insere o novo usuário no banco
                self.cursor.execute('INSERT INTO usuarios (login, senha, admin) VALUES (?, ?, 0)', (novo_usuario, hashed_senha.decode('utf-8')))
                print("Novo usuário cadastrado com sucesso!")
                break
            else:
                print("Nome e senha do usuário devem ter no mínimo 3 caracteres. Tente novamente.")

    def remover_usuario(self):
        usuario_para_remover = input("Digite o nome do usuário a ser removido: ")

        # Verifica se o usuário existe
        self.cursor.execute('SELECT * FROM usuarios WHERE login = ?', (usuario_para_remover,))
        usuario = self.cursor.fetchone()

        if usuario:
            self.cursor.execute('DELETE FROM usuarios WHERE login = ?', (usuario_para_remover,))
            print(f"Usuário '{usuario_para_remover}' removido com sucesso!")
        else:
            print(f"Usuário '{usuario_para_remover}' não encontrado.")

    def alterar_senha(self):
        usuario_para_alterar = input("Digite o nome do usuário para alterar a senha: ")

        # Verifica se o usuário existe
        self.cursor.execute('SELECT * FROM usuarios WHERE login = ?', (usuario_para_alterar,))
        usuario = self.cursor.fetchone()

        if usuario:
            nova_senha = getpass.getpass("Digite a nova senha: ")

            if len(nova_senha) >= 3:
                hashed_senha = bcrypt.hashpw(nova_senha.encode('utf-8'), bcrypt.gensalt())

                # Atualiza a senha do usuário no banco de dados
                self.cursor.execute('UPDATE usuarios SET senha = ? WHERE login = ?', (hashed_senha.decode('utf-8'), usuario_para_alterar))
                print(f"Senha do usuário '{usuario_para_alterar}' alterada com sucesso!")
            else:
                print("A nova senha deve ter no mínimo 3 caracteres. Tente novamente.")
        else:
            print(f"Usuário '{usuario_para_alterar}' não encontrado.")

    def consultar_banco_dados(self):
        self.cursor.execute('SELECT * FROM usuarios')
        usuarios = self.cursor.fetchall()

        print("\nConsulta ao Banco de Dados:")
        for usuario in usuarios:
            print(f"ID: {usuario[0]}, Login: {usuario[1]}, Admin: {usuario[3]}")

    def registrar_log_acesso(self, usuario):
        self.cursor.execute('INSERT INTO logs (usuario) VALUES (?)', (usuario,))

    def consultar_log_acesso(self):
        self.cursor.execute('SELECT * FROM logs')
        logs = self.cursor.fetchall()

        print("\nLog de Acesso:")
        for log in logs:
            print(f"ID: {log[0]}, Usuário: {log[1]}, Horário: {log[2]}")

def main():
    db_manager = DatabaseManager()

    while True:
        print("\nMenu de Login:")
        print("1 - Login")
        print("EXIT - Sair")
        opcao1 = input("Escolha uma opção: ")
        opcao1 = opcao1.upper()
        
        if opcao1 == '1':
            db_manager.fazer_login()
        elif opcao1 == 'EXIT':
            print("Saindo do programa. Até mais!")
            break
        else:
            print("Opção inválida. Tente novamente.")

if __name__ == "__main__":
    main()
