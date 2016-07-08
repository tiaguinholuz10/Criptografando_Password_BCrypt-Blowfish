package br.com.tt;

import org.mindrot.jbcrypt.BCrypt;

/**
 * Este código utiliza jBCrypt. http://www.mindrot.org/projects/jBCrypt/
 * https://gist.github.com/craSH/5217757
 */

public class Password {

	/*
	 * Defini a carga de trabalho bcrypt para gerar hashes de senha.Entre 10-31
	 * é um valor válido.
	 */
	private static int workload = 12;

	/*
	 * Este método pode ser usado para gerar uma cadeia que representa uma senha
	 * de conta Adequado para armazenar em um banco de dados. Será uma cripta
	 * OpenBSD-style (3) formatado Cadeia de hash de comprimento = 60 A carga de
	 * trabalho bcrypt é especificado na variável estática acima, um valor de 10
	 * a 31. A carga de trabalho de 12 é um padrão de segurança muito razoável a
	 * partir de 2013. Este trata automaticamente a geração de sal de 128 bits
	 * segura e armazenamento dentro do hash.
	 * 
	 * @ Param password_plaintext senha de texto da conta, tal como previsto
	 * durante a criação da conta, Ou ao mudar a senha de uma conta.
	 * 
	 * @return String - uma cadeia de comprimento 60, que é a senha bcrypt hash
	 * em crypt (3) formato.
	 */
	public static String hashPassword(String password_plaintext) {
		String salt = BCrypt.gensalt(workload);
		String hashed_password = BCrypt.hashpw(password_plaintext, salt);

		return (hashed_password);
	}

	/*
	 * Este método pode ser utilizado para verificar um hash calculado a partir
	 * de um texto simples (por exemplo, durante um login Pedido) com a de um
	 * hash armazenado a partir de um banco de dados. O hash de senha do banco
	 * de dados Deve ser passado como o segundo variável.
	 * 
	 * @ Param password_plaintext senha de texto da conta, conforme previsto
	 * durante uma solicitação de login
	 * 
	 * @ Param stored_hash hash de senha armazenadas da conta, recuperada a
	 * partir do banco de dados de autorização
	 * 
	 * @return Boolean - true se a senha corresponde à senha do hash armazenado,
	 * caso contrário false
	 */
	public static boolean checkPassword(String password_plaintext, String stored_hash) {
		boolean password_verified = false;

		if (null == stored_hash || !stored_hash.startsWith("$2a$"))
			throw new java.lang.IllegalArgumentException("Hash inválido fornecido para comparação");

		password_verified = BCrypt.checkpw(password_plaintext, stored_hash);

		return (password_verified);
	}

	/*
	 * Um caso de teste simples para o método principal, verificar se um hash
	 * teste de pré-gerado verifica com sucesso Para a senha que ele representa,
	 * e também gerar um novo hash e garantir que as novas verifica de hash
	 * apenas o mesmo.
	 */
	public static void main(String[] args) {
		String test_passwd = "123456789acsd";
		String test_hash = "$2a$12$907.4Kn4hOB36KbebAwky.lywvOcpGsPFSkmZUUv8KDRahNmRa2MS"; 

		System.out.println("Teste bcrypt senha hashing e verificação");
		System.out.println();
		System.out.println("Test_passwd " + test_passwd);
		System.out.println("test_hash   " + test_hash);
		System.out.println();
		System.out.println("teste de hash password...");

		String computed_hash = hashPassword(test_passwd);
		System.out.println("Test computado hash igual: " + computed_hash);
		System.out.println("Tamanho do HASH do password " + test_passwd + " = " + computed_hash.length());
		System.out.println();
		System.out.println("Verifica se o hash armazenado combina com hash gerado...");
		System.out.println();

		// Verifica se o hash gerado com a senha'123456789acsd' é igual ao hash
		// Armazenado na Variavel 'test_hash'
		String compare_test = checkPassword(test_passwd, test_hash) ? "Passwords combina" : "Passwords não combina";

		// Compara os hash Gerados entre test_passwd e computed_hash
		String compare_computed = checkPassword(test_passwd, computed_hash) ? "Passwords combina"
				: "Passwords não combina";

		System.out.println("Verifique o hash armazenado:   " + compare_test);
		System.out.println("Verifique o hash calculado:    " + compare_computed);

	}

}