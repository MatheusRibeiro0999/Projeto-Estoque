import sqlite3
import bcrypt
import getpass

# cria tabela de usuários
def criar_tabela():
    conexao = sqlite3.connect('usuarios.db')
    cursor = conexao.cursor()

    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            login TEXT,
            senha TEXT,
            admin INTEGER
        )
    ''')

    conexao.commit()
    conexao.close()

# cadastra o adm
def cadastrar_administrador():
    conexao = sqlite3.connect('usuarios.db')
    cursor = conexao.cursor()

    # Verifica se já tem adm
    cursor.execute('SELECT * FROM usuarios WHERE admin = 1')
    admin_existente = cursor.fetchone()

    if admin_existente:
        print("Já existe um administrador cadastrado.")
        conexao.close()
        return

    while True:
        login = input("Digite o nome do administrador: ")
        senha = getpass.getpass("Digite a senha do administrador: ")

        if len(login) >= 3 and len(senha) >= 3:
            hashed_senha = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt())

            # Insere o adm no banco
            cursor.execute('INSERT INTO usuarios (login, senha, admin) VALUES (?, ?, 1)', (login, hashed_senha.decode('utf-8')))
            print("Administrador cadastrado com sucesso!")
            break
        else:
            print("Nome e senha do administrador devem ter no mínimo 3 caracteres. Tente novamente.")

    conexao.commit()
    conexao.close()

#realiza login
def fazer_login():
    conexao = sqlite3.connect('usuarios.db')
    cursor = conexao.cursor()

    while True:
        login = input("Digite o nome de usuário: ")
        senha = getpass.getpass("Digite a senha: ")

        # Verifica se o login existe
        cursor.execute('SELECT * FROM usuarios WHERE login = ?', (login,))
        usuario = cursor.fetchone()

        if usuario and bcrypt.checkpw(senha.encode('utf-8'), usuario[2].encode('utf-8')):
            print("Login bem-sucedido!")

            if usuario[3] == 1:  # Verifica se é um administrador
                menu_administracao()
            break
        else:
            print("Login ou senha incorretos. Tente novamente.")

    conexao.close()

# Função para o menu de admin
def menu_administracao():
    while True:
        print("\nMenu de Administração:")
        print("1 - Adicionar Usuário")
        print("2 - Remover Usuário")
        print("3 - Alterar Senha")
        print("4 - Consultar Banco de Dados")
        print("5 - Sair")
        opcao = input("Escolha uma opção: ")

        if opcao == '1':
            adicionar_usuario()
        elif opcao == '2':
            remover_usuario()
        elif opcao == '3':
            alterar_senha()
        elif opcao == '4':
            consultar_banco_dados()
        elif opcao == '5':
            print("Saindo do menu de administração.")
            break
        else:
            print("Opção inválida. Tente novamente.")

# adiciona novo usuário
def adicionar_usuario():
    conexao = sqlite3.connect('usuarios.db')
    cursor = conexao.cursor()

    while True:
        novo_usuario = input("Digite o nome do novo usuário: ")
        nova_senha = getpass.getpass("Digite a senha do novo usuário: ")

        if len(novo_usuario) >= 3 and len(nova_senha) >= 3:
            hashed_senha = bcrypt.hashpw(nova_senha.encode('utf-8'), bcrypt.gensalt())

            # Insere o novo usuário no banco
            cursor.execute('INSERT INTO usuarios (login, senha, admin) VALUES (?, ?, 0)', (novo_usuario, hashed_senha.decode('utf-8')))
            print("Novo usuário cadastrado com sucesso!")
            break
        else:
            print("Nome e senha do usuário devem ter no mínimo 3 caracteres. Tente novamente.")

    conexao.commit()
    conexao.close()

# Função para remover um usuário
def remover_usuario():
    conexao = sqlite3.connect('usuarios.db')
    cursor = conexao.cursor()

    usuario_para_remover = input("Digite o nome do usuário a ser removido: ")

    # Verifica se o usuário existe
    cursor.execute('SELECT * FROM usuarios WHERE login = ?', (usuario_para_remover,))
    usuario = cursor.fetchone()

    if usuario:
        cursor.execute('DELETE FROM usuarios WHERE login = ?', (usuario_para_remover,))
        print(f"Usuário '{usuario_para_remover}' removido com sucesso!")
    else:
        print(f"Usuário '{usuario_para_remover}' não encontrado.")

    conexao.commit()
    conexao.close()

# Função para alterar a senha do usuário
def alterar_senha():
    conexao = sqlite3.connect('usuarios.db')
    cursor = conexao.cursor()

    usuario_para_alterar = input("Digite o nome do usuário para alterar a senha: ")

    # Verifica se o usuário existe
    cursor.execute('SELECT * FROM usuarios WHERE login = ?', (usuario_para_alterar,))
    usuario = cursor.fetchone()

    if usuario:
        nova_senha = getpass.getpass("Digite a nova senha: ")

        if len(nova_senha) >= 3:
            hashed_senha = bcrypt.hashpw(nova_senha.encode('utf-8'), bcrypt.gensalt())

            # Atualiza a senha do usuário no banco de dados
            cursor.execute('UPDATE usuarios SET senha = ? WHERE login = ?', (hashed_senha.decode('utf-8'), usuario_para_alterar))
            print(f"Senha do usuário '{usuario_para_alterar}' alterada com sucesso!")
        else:
            print("A nova senha deve ter no mínimo 3 caracteres. Tente novamente.")
    else:
        print(f"Usuário '{usuario_para_alterar}' não encontrado.")

    conexao.commit()
    conexao.close()

# admin consulta o banco
def consultar_banco_dados():
    conexao = sqlite3.connect('usuarios.db')
    cursor = conexao.cursor()

    
    cursor.execute('SELECT * FROM usuarios')
    usuarios = cursor.fetchall()

    
    print("\nConsulta ao Banco de Dados:")
    for usuario in usuarios:
        print(f"ID: {usuario[0]}, Login: {usuario[1]}, Admin: {usuario[3]}")

    conexao.close()

# Função principal
def main():
    criar_tabela()

    # Verifica se é a primeira execução
    conexao = sqlite3.connect('usuarios.db')
    cursor = conexao.cursor()
    cursor.execute('SELECT * FROM usuarios')
    primeiro_uso = not cursor.fetchone()
    conexao.close()

    if primeiro_uso:
        print("Bem-vindo! Vamos cadastrar o administrador.")
        cadastrar_administrador()

    while True:
        print("\nMenu de Login:")
        print("1 - Login")
        print("2 - Sair")
        opcao = input("Escolha uma opção: ")

        if opcao == '1':
            fazer_login()
        elif opcao == '2':
            print("Saindo do programa. Até mais!")
            break
        else:
            print("Opção inválida. Tente novamente.")

if __name__ == "__main__":
    main()
