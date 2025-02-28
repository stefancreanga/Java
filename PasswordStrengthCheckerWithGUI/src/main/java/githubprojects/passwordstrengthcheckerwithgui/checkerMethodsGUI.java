package githubprojects.passwordstrengthcheckerwithgui;

import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class checkerMethodsGUI {
    public boolean isLengthValid(String password, int minLength) {
        return password.length() >= minLength;
    }

    public boolean containsUppercase(String password) {
        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) {
                return true;
            }
        }
        return false;
    }

    public boolean containsLowercase(String password) {
        for (char c : password.toCharArray()) {
            if (Character.isLowerCase(c)) {
                return true;
            }
        }
        return false;
    }

    public boolean containsDigit(String password) {
        for (char c : password.toCharArray()) {
            if (Character.isDigit(c)) {
                return true;
            }
        }
        return false;
    }

    public boolean containsSpecialCharacter(String password) {
        String specialCharacters = "!@#$%^&*()-_=+[]{}|;:,.<>?/~`";
        for (char c : password.toCharArray()) {
            if (specialCharacters.contains(String.valueOf(c))) {
                return true;
            }
        }
        return false;
    }

    public boolean hasRepeatedCharacters(String password) {
        for (int i = 0; i < password.length() - 1; i++) {
            if (password.charAt(i) == password.charAt(i + 1)) {
                return true;
            }
        }
        return false;
    }

    private static String sha1(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] result = md.digest(input.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : result) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString().toUpperCase();
    }

    public static boolean isBreached(String password) {
        try {
            String hash = sha1(password);
            String prefix = hash.substring(0, 5);
            String suffix = hash.substring(5);

            URL url = new URL("https://api.pwnedpasswords.com/range/" + prefix);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");

            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains(suffix.toUpperCase())) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            System.out.println("Error checking HIBP: " + e.getMessage());
            return false;
        }
    }

    public String shuffleString(String string) {
        List<Character> characters = new ArrayList<>();
        for (char c : string.toCharArray()) {
            characters.add(c);
        }
        StringBuilder shuffled = new StringBuilder(string.length());
        Random random = new SecureRandom();
        while (!characters.isEmpty()) {
            int index = random.nextInt(characters.size());
            shuffled.append(characters.remove(index));
        }
        return shuffled.toString();
    }

    public String evaluatePasswordStrength(String password, ArrayList<String> suggestions) {
        int score = 0;
        int minLength = 8;

        if (isLengthValid(password, minLength)) {
            score++;
        } else {
            suggestions.add("- try a longer password");
        }
        if (containsUppercase(password)) {
            score++;
        } else {
            suggestions.add("- try using UPPERCASE");
        }
        if (containsLowercase(password)) {
            score++;
        } else {
            suggestions.add("- TRY USING lowercase");
        }
        if (containsDigit(password)) {
            score++;
        } else {
            suggestions.add("- try using digits");
        }
        if (containsSpecialCharacter(password)) {
            score++;
        } else {
            suggestions.add("- try using $pecial (haracters");
        }
        if (!hasRepeatedCharacters(password)) {
            score++;
        } else {
            suggestions.add("- try nnot tto rreppeaatt chharraccterrs");
        }
        if (checkerMethodsGUI.isBreached(password)) {
            suggestions.add("- choose another password");
            return "breached";
        }

        if (score >= 6) {
            return "strong";
        } else if (score >= 4) {
            return "moderate";
        } else {
            return "weak";
        }
    }

    public String generatePassword(List<Long> keystrokeTimings) {

        // This part of the code calculates the number of miliseconds in number of hours (which is given by the day of the month)
        LocalDate currentDate = LocalDate.now();
        int dayOfMonth = currentDate.getDayOfMonth();
        long millisecondsInHours = dayOfMonth * 60 * 60 * 1000;

        // The result is then XORed with the time between keystrokes
        long seed = millisecondsInHours;
        for (long timing : keystrokeTimings) {
            seed ^= timing;
        }

        Random random = new SecureRandom();
        random.setSeed(seed);

        // Defines what types of characters to use
        String upperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String lowerCase = "abcdefghijklmnopqrstuvwxyz";
        String digits = "0123456789";
        String specialCharacters = "!#$%^&*";
        String allCharacters = upperCase + lowerCase + digits + specialCharacters;

        // Generates password ensuring it has atleast one of all of the above characteristics
        StringBuilder password = new StringBuilder();
        password.append(upperCase.charAt(random.nextInt(upperCase.length())));
        password.append(lowerCase.charAt(random.nextInt(lowerCase.length())));
        password.append(digits.charAt(random.nextInt(digits.length())));
        password.append(specialCharacters.charAt(random.nextInt(specialCharacters.length())));
        for (int i = 4; i < 12; i++) {
            password.append(allCharacters.charAt(random.nextInt(allCharacters.length())));
        }

        // Shuffle the password to ensure randomness
        password = new StringBuilder(shuffleString(password.toString()));

        // In case there are repeated characters, shuffle again
        while(hasRepeatedCharacters(password.toString())){
            password = new StringBuilder(shuffleString(password.toString()));
        }

        return password.toString();
    }

    public void checkPasswordStrength(TextField passwordField, TextArea resultArea) {
        String password = passwordField.getText();
        if(password.equals("")){
            resultArea.setText("There's no password to check!");
        }else{
            ArrayList<String> suggestions = new ArrayList<>();
            String strength = evaluatePasswordStrength(password, suggestions);
            if(strength!="breached"){
                resultArea.setText("The password is " + strength + "\n");
                if(suggestions.isEmpty()){
                    resultArea.appendText("No suggestions to improve your password.");
                }else{
                    resultArea.appendText("Suggestions:\n");
                    for (String suggestion : suggestions) {
                        resultArea.appendText(suggestion + "\n");
                    }
                }
            } else{
                resultArea.setText("The password has been " + strength + ", change your password immediately." + "\n");

            }

        }
    }
}
