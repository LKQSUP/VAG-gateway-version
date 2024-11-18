import logging
from openobd import *
import streamlit as st
import configparser

# Load configuration from config.ini
config = configparser.ConfigParser()
config.read("config.ini")

# Retrieve API keys and credentials
try:
    client_id = config["api_keys"]["OPENOBD_PARTNER_CLIENT_ID"]
    client_secret = config["api_keys"]["OPENOBD_PARTNER_CLIENT_SECRET"]
    api_key = config["api_keys"]["OPENOBD_PARTNER_API_KEY"]
    cluster_id = config["api_keys"]["OPENOBD_CLUSTER_ID"]
    grpc_host = config["api_keys"]["OPENOBD_GRPC_HOST"]
except KeyError as e:
    st.error(f"Missing key in config file: {e}")
    st.stop()

# Set up logging
logging.basicConfig(level=logging.INFO)
logging.info("Author: OSIAS")
logging.info("YAYRA.OSIAS@LKQBEGIUM.BE")

# Define the log file path
log_file_path = "Adblue_info_log.txt"

# Function to log data to a file
def log_response(data):
    with open(log_file_path, "a") as log_file:
        log_file.write(data + "\n")

# Streamlit user input for ticket ID
st.title("AdBlue Module Check")
ticket_id = st.text_input("Enter Ticket ID (numbers only):")
run_check = st.button("Run Check")

# Validate ticket ID input and execute check if button is pressed
if run_check:
    if ticket_id.isdigit():
        try:
            # Initialize OpenOBD with credentials
            openobd = OpenOBD(
                client_id=client_id,
                client_secret=client_secret,
                api_key=api_key,
                cluster_id=cluster_id,
                grpc_host=grpc_host
            )
            openobd_session = openobd.start_session_on_ticket(ticket_id)
            SessionTokenHandler(openobd_session)

            # Configure buses
            bus_configs = [
                (BusConfiguration(
                    bus_name="bus_6_14",
                    can_bus=CanBus(pin_plus=6,
                                   pin_min=14,
                                   can_protocol=CanProtocol.CAN_PROTOCOL_ISOTP,
                                   can_bit_rate=CanBitRate.CAN_BIT_RATE_500,
                                   transceiver=TransceiverSpeed.TRANSCEIVER_SPEED_HIGH))),
                (BusConfiguration(
                    bus_name="bus_3_11",
                    can_bus=CanBus(pin_plus=3,
                                   pin_min=11,
                                   can_protocol=CanProtocol.CAN_PROTOCOL_ISOTP,
                                   can_bit_rate=CanBitRate.CAN_BIT_RATE_500,
                                   transceiver=TransceiverSpeed.TRANSCEIVER_SPEED_HIGH)))
            ]
            bus_config_stream = StreamHandler(openobd_session.configure_bus)
            bus_config_stream.send_and_close(bus_configs)
            
            # Define an ISO-TP channel for the ECU_motor
            adb_channel = IsotpChannel(bus_name="bus_6_14",
                                       request_id=0x7E6,
                                       response_id=0x7EE,
                                       padding=Padding.PADDING_ENABLED)
            adb = IsotpSocket(openobd_session, adb_channel)

            # Initialize module check
            requests = {
                "VIN": "22F190",
                "Factory Part Number": "22F187",
                "Hardware Number": "22F191",
                "Motor Type + part number": "22F19E",
                "Supplier Number": "22F18A",
                "SW Version": "22F189",
            }

            # Track if a corrupt ECU is detected
            corrupt_ecu_detected = False

            for name, command in requests.items():
                try:
                    response = adb.request(command, tries=2, timeout=5)
                    if response:
                        if response == "7F2231":  # Check for specific negative response
                            st.error("Negative response: Out of range")
                            log_response(f"{name}: Negative response: Out of range")
                        else:
                            response_hex = response[6:]
                            try:
                                data = bytes.fromhex(response_hex).decode("utf-8")
                                st.write(f"{name}: {data}")
                                log_response(f"{name}: {data}")

                                # Check for corrupt hardware number
                                if name == "Hardware Number" and data == "237G00001R":
                                    corrupt_ecu_detected = True
                                    log_response("Corrupt ECU detected!")
                            except UnicodeDecodeError:
                                st.write(f"{name}: (Could not decode to UTF-8) {response_hex}")
                                log_response(f"{name}: (Could not decode to UTF-8) {response_hex}")
                    else:
                        st.warning("Request failed")
                        log_response("Request failed")
                        
                except Exception as e:
                    error_msg = f"Request failed: {e}"
                    logging.error(error_msg)
                    log_response(error_msg)

            # Display final status
            if corrupt_ecu_detected:
                st.error("Corrupt unit detected! AdBlue module must be changed.")
            else:
                st.success("ECU is OK. Proceed with the update.")

            adb.stop_stream()
            result = ServiceResult(result=[Result.RESULT_SUCCESS])
            openobd_session.finish(result)
            
        except OpenOBDException as e:
            st.warning("Invalid ID or credentials. Please try again.")
            logging.error(f"OpenOBDException: {e}")
            log_response(f"OpenOBDException: {e}")

    else:
        st.warning("Please enter a valid numeric Ticket ID.")
