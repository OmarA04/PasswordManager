#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <ctime> // Added for time functions
#include <openssl/sha.h> // Added for SHA hashing

// Structure to hold username and password
struct Credential {
    std::string username; // Variable to store the username
    std::string password; // Variable to store the password

    // Constructor for Credential structure
    Credential(const std::string& uname, const std::string& pwd) : username(uname), password(pwd) {}
};

class PasswordManager {
private:
    std::vector<std::pair<std::string, std::vector<Credential>>> userCredentials; // Container to store user credentials

    // Caesar cipher encryption function
    std::string encrypt(const std::string& text, int shift) {
        std::string result = ""; // Variable to store the encrypted text

        // Loop through each character in the input text
        for (char ch : text) {
            if (isalpha(ch)) { // Check if the character is alphabetic
                // Encrypt alphabetic characters using Caesar cipher algorithm
                char shifted = (isupper(ch)) ? 'A' + (ch - 'A' + shift) % 26 : 'a' + (ch - 'a' + shift) % 26;
                result += shifted; // Append the encrypted character to the result string
            } else {
                result += ch; // Non-alphabetic characters remain unchanged
            }
        }

        return result; // Return the encrypted text
    }

    // Caesar cipher decryption function
    std::string decrypt(const std::string& text, int shift) {
        return encrypt(text, 26 - shift); // Decrypt by shifting in the opposite direction
    }

public:
    // Function to save new username and password for the currently logged-in user
    void saveCredential(const std::string& loggedInUser, const std::string& username, const std::string& password) {
        std::string encryptedPassword = encrypt(password, 3); // Encrypt the password using Caesar cipher with a shift of 3 positions

        // Iterate through the userCredentials vector to find the logged-in user
        for (auto& user : userCredentials) {
            if (user.first == loggedInUser) { // If the logged-in user is found
                user.second.emplace_back(username, encryptedPassword); // Add the new username and encrypted password to the user's credentials
                std::cout << "Username and password saved successfully!" << std::endl; // Display success message
                return; // Exit the function
            }
        }
        // If no entry is found for the logged-in user, create a new entry with the username and encrypted password
        userCredentials.emplace_back(loggedInUser, std::vector<Credential>{{username, encryptedPassword}});
        std::cout << "Username and password saved successfully!" << std::endl; // Display success message
    }

    // Function to retrieve saved credentials for the currently logged-in user
    void retrieveCredentials(const std::string& loggedInUser) {
        // Iterate through the userCredentials vector to find the logged-in user's credentials
        for (const auto& user : userCredentials) {
            if (user.first == loggedInUser) { // If the logged-in user is found
                std::cout << "Saved credentials for user '" << loggedInUser << "':" << std::endl; // Display message indicating saved credentials
                // Iterate through the user's credentials and decrypt the passwords before displaying
                for (const auto& cred : user.second) {
                    std::cout << "Username: " << cred.username << ", Password: " << decrypt(cred.password, 3) << std::endl; // Decrypt the password before displaying
                }
                return; // Exit the function
            }
        }
        std::cout << "No credentials found for user '" << loggedInUser << "'" << std::endl; // Display message if no credentials are found for the logged-in user
    }

    // SHA hashing function 
    std::string hashPassword(const std::string& password) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, password.c_str(), password.size());
        SHA256_Final(hash, &sha256);
        
        std::string hashedPassword;
        for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            char hex[3];
            sprintf(hex, "%02x", hash[i]);
            hashedPassword += hex;
        }
        return hashedPassword; // Return the hashed password
    }

    // Function to generate a random password of specified length
    std::string generateRandomPassword(int length) {
        const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"; // Define character set for random password generation
        std::string password;
        srand(time(0)); // Seed for random number generation
        // Generate random password characters from the character set based on the specified length
        for (int i = 0; i < length; ++i) {
            password += charset[rand() % charset.length()];
        }
        return password; // Return the generated random password
    }
};



class UserManager {
private:
    std::vector<std::pair<std::string, std::string>> users; // Vector to store usernames and hashed passwords

public:
    // Function to register a new user
    void registerUser(const std::string& username, const std::string& password) {
        PasswordManager passwordManager;
        std::string hashedPassword = passwordManager.hashPassword(password); // Hash the password using SHA256 algorithm
        users.emplace_back(username, hashedPassword); // Add the username and hashed password to the users vector
        std::cout << "User registered successfully!" << std::endl; // Display success message
    }

    // Function to authenticate user
    bool authenticate(const std::string& username, const std::string& password) {
        PasswordManager passwordManager;
        std::string hashedPassword = passwordManager.hashPassword(password); // Hash the password using SHA256 algorithm

        // Iterate through the users vector to find the matching username and hashed password
        for (const auto& user : users) {
            if (user.first == username && user.second == hashedPassword) { // If the username and hashed password match
                return true; // Return true to indicate successful authentication
            }
        }
        return false; // Return false if no matching username and hashed password are found
    }
};

int main() {
    UserManager userManager; // Instantiate UserManager object
    PasswordManager passwordManager; // Instantiate PasswordManager object
    std::string loggedInUser; // Variable to store the logged-in user's username

    std::cout << "Welcome to the Password Manager!" << std::endl; // Display welcome message

    while (true) { // Infinite loop to display menu options
        std::cout << "\nMenu:" << std::endl;
        std::cout << "1. Register" << std::endl;
        std::cout << "2. Login" << std::endl;
        std::cout << "3. Exit" << std::endl;
        std::cout << "Choose an option: ";

        int choice; // Variable to store user's choice
        std::cin >> choice; // Read user's choice
        std::cin.ignore(); // Clear input buffer

        switch (choice) {
            case 1: { // Option to register a new user
                std::string username, password;
                std::cout << "Enter a new username: ";
                std::getline(std::cin, username); // Read new username
                std::cout << "Enter a password: ";
                std::getline(std::cin, password); // Read password
                userManager.registerUser(username, password); // Register new user
                break;
            }
            case 2: { // Option to login
                std::string username, password;
                std::cout << "Enter your username: ";
                std::getline(std::cin, username); // Read username
                std::cout << "Enter your password: ";
                std::getline(std::cin, password); // Read password
                if (userManager.authenticate(username, password)) { // Check if authentication is successful
                    loggedInUser = username; // Set logged-in user
                    std::cout << "Login successful!" << std::endl; // Display success message
                    while (true) { // Inner loop for logged-in user options
                        std::cout << "\nOptions:" << std::endl;
                        std::cout << "1. Save a new username and password" << std::endl;
                        std::cout << "2. Retrieve saved username & password" << std::endl;
                        std::cout << "3. Generate a random password" << std::endl;
                        std::cout << "4. Logout" << std::endl;
                        std::cout << "Choose an option: ";
                        std::cin >> choice; // Read user's choice
                        std::cin.ignore(); // Clear input buffer
                        switch (choice) {
                            case 1: { // Option to save new credentials
                                std::string newUsername, newPassword;
                                std::cout << "Enter a new username: ";
                                std::getline(std::cin, newUsername); // Read new username
                                std::cout << "Enter a new password: ";
                                std::getline(std::cin, newPassword); // Read new password
                                passwordManager.saveCredential(loggedInUser, newUsername, newPassword); // Save new credentials
                                break;
                            }
                            case 2: { // Option to retrieve saved credentials
                                passwordManager.retrieveCredentials(loggedInUser); // Retrieve saved credentials
                                break;
                            }
                            case 3: { // Option to generate a random password
                                int passwordLength;
                                std::cout << "Enter the number of characters for the password: ";
                                std::cin >> passwordLength; // Read password length
                                std::cin.ignore(); // Clear input buffer
                                std::string newPassword = passwordManager.generateRandomPassword(passwordLength); // Generate random password
                                std::cout << "Generated Password: " << newPassword << std::endl; // Display generated password
                                break;
                            }
                            case 4: { // Option to logout
                                std::cout << "Logging out..." << std::endl;
                                loggedInUser = ""; // Clear logged-in user
                                goto logout; // Exit inner loop
                            }
                            default: // Invalid option
                                std::cout << "Invalid option. Please choose again." << std::endl;
                                break;
                        }
                    }
                } else {
                    std::cout << "Authentication failed. Invalid username or password." << std::endl; // Display authentication failure message
                }
                break;
            }
            case 3: { // Option to exit the program
                std::cout << "Exiting..." << std::endl; // Display exit message
                return 0; // Return 0 to indicate successful termination of the program
            }
            default: // Invalid option
                std::cout << "Invalid option. Please choose again." << std::endl; // Display invalid option message
        }
        logout:; // Label to exit inner loop
    }
    return 0;
}

