package controllers;


import helpers.HashUtils;
import models.User;
import play.i18n.Messages;
import play.mvc.Controller;

//imports extra para la solución de bloqueo automático
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class Secure extends Controller {
	private static final int MAX_ATTEMPTS = 3; // Se establece que se puede fallar solo 3 veces sin ser bloqueado.
    private static final long LOCK_TIME_MS = TimeUnit.MINUTES.toMillis(10); // Se establece un tiempo de 10mins de bloqueo
    private static final Map<String, InicioSesion> intentosInicioSesion = new HashMap<>();
     
    public static void login(){
        render();
    }

    public static void logout(){
        session.remove("password");
        login();
    }

    public static void authenticate(String username, String password){
    	
    	//Verificación para asegurar que el usuario no está bloqueado. si lo está, no permite loggear.
    	long currentTime = System.currentTimeMillis();
    	InicioSesion intento = intentosInicioSesion.getOrDefault(username, new InicioSesion(0, 0));
        if (intento.bloqueoHasta > currentTime) {
            flash.put("error", "Cuenta bloqueada. Intentelo de nuevo más tarde.");
            login();
            return;
        }
    	
        User u = User.loadUser(username);
        if (u != null && u.getPassword().equals(HashUtils.getMd5(password))){
            session.put("username", username);
            session.put("password", password);
            intentosInicioSesion.remove(username);
            Application.index();
        }else{ 
        	intento.intentosFallidos++;
        	if (intento.intentosFallidos >= MAX_ATTEMPTS) {
        		intento.bloqueoHasta = currentTime + LOCK_TIME_MS;
                flash.put("error", "Cuenta bloqueada por múltiples intentos fallidos.");
            } else {
                flash.put("error", Messages.get("Public.login.error.credentials") + 
                          " Intentos restantes: " + (MAX_ATTEMPTS - intento.intentosFallidos));
            }
        	intentosInicioSesion.put(username, intento); // Guarda el estado actualizado
            login();
        }

    }
    // Clase interna para registrar los intentos de inicio de sesión
    private static class InicioSesion {
        int intentosFallidos; // Número de intentos fallidos
        long bloqueoHasta;    // Hora hasta la cual la cuenta estará bloqueada

        InicioSesion(int intentosFallidos, long bloqueoHasta) {
            this.intentosFallidos = intentosFallidos;
            this.bloqueoHasta = bloqueoHasta;
        }
    }
}
