import socket
import threading
import json
import sqlite3
import datetime

# Dictionary to store client connections
passenger_connections = {}
driver_connections = {}
all_drivers_data = {}

# ANSI color escape codes
COLOR_GREEN = "\033[92m"
COLOR_RED = "\033[91m"
COLOR_RESET = "\033[0m"

# Response types
RESPONSE_LOGIN = "login"
RESPONSE_DRIVER_DATA = "driver_data"
RESPONSE_PASSENGER_DATA = "passenger_data"

# Function to authenticate user credentials against the SQLite database
def authenticate_user(email, password, user_type):
    try:
        # Connect to the SQLite database
        connection = sqlite3.connect('Database/AccountSystem.db')
        cursor = connection.cursor()

        # Execute the query to fetch user details
        cursor.execute("SELECT * FROM AccountDB WHERE Email=? AND Password=? AND Type=?", (email, password, user_type))
        user = cursor.fetchone()

        # Close the database connection
        connection.close()

        # Check if user exists and credentials match
        if user:
            return True
        else:
            return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False

# Function to handle client connection
def handle_client(client_socket):
    try:
        while True:
            # Receive JSON data from the client
            data = client_socket.recv(1024).decode()
            if not data:
                break  # Exit the loop if no data is received
            user_data = json.loads(data)
            print(user_data)

            # Check response type
            response_type = user_data.get('response_type')

            if response_type == RESPONSE_LOGIN:
                # Authenticate user
                email = user_data['email']
                password = user_data['password']
                user_type = user_data['type']

                auth_status = authenticate_user(email, password, user_type)

                if auth_status:
                    # Authentication successful
                    client_socket.sendall(json.dumps({'response_type': RESPONSE_LOGIN, 'status': 'success'}).encode())
                    
                    # Log user login
                    with open("login_logs.log", "a") as log_file:
                        log_text = f"Logged in: {email}, Type: {user_type}, Connection: {client_socket.getpeername()}, Time: {datetime.datetime.now()}\n"
                        if user_type == 'Passenger':
                            log_text = f"{COLOR_GREEN}{log_text}{COLOR_RESET}"
                        elif user_type == 'Driver':
                            log_text = f"{COLOR_RED}{log_text}{COLOR_RESET}"
                        log_file.write(log_text)
                    
                    # Maintain connection with authenticated client
                    if user_type == 'Passenger':
                        passenger_connections[email] = client_socket
                    elif user_type == 'Driver':
                        driver_connections[email] = client_socket
                else:
                    # Authentication failed
                    client_socket.sendall(json.dumps({'response_type': RESPONSE_LOGIN, 'status': 'failure'}).encode())

            elif response_type == RESPONSE_DRIVER_DATA:
                # Parse driver data
                print("response type driverdata")
                driver_id = user_data.get('driver_id')
                all_drivers_data[driver_id] = user_data
                print(f"Received driver data: {user_data}")

            elif response_type == RESPONSE_PASSENGER_DATA:
                # Parse passenger data
                print("response type passanger data")
                passenger_id = user_data.get('passenger_id')
                source = user_data.get('source')
                destination = user_data.get('destination')
                print(f"received passanger data: {user_data} ")
                
                # Search for available drivers
                available_drivers = [driver_data for driver_data in all_drivers_data.values() if driver_data['source'] == source and driver_data['destination'] == destination]
                
                # Prepare response for the passenger
                response = {
                    'passenger_id': passenger_id,
                    'available_drivers': available_drivers
                }
                
                # Send response to the passenger
                client_socket.sendall(json.dumps({'response_type': RESPONSE_PASSENGER_DATA, 'data': response}).encode())
                
                # Clear the buffer
                client_socket.recv(4096)  # Adjust buffer size as needed

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Close client connection
        client_socket.close()
# Main function to start the CA server
def main():
    # Server configuration
    server_host = '127.0.0.1'
    server_port = 4771

    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the address
    server_socket.bind((server_host, server_port))

    # Start listening for incoming connections
    server_socket.listen(5)
    print(f"Central Authority server started on {server_host}:{server_port}")

    try:
        while True:
            # Accept incoming connection
            client_socket, client_address = server_socket.accept()
            print(f"Connection established with {client_address}")

            # Create a new thread to handle the client connection
            client_thread = threading.Thread(target=handle_client, args=(client_socket,))
            client_thread.start()
    except KeyboardInterrupt:
        print("Server stopped.")
    finally:
        # Close the server socket
        server_socket.close()

if __name__ == "__main__":
    main()
