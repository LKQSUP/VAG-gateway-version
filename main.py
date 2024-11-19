import streamlit as st
import logging
import os
from openobd import OpenOBD, BusConfiguration, CanBus, CanProtocol, CanBitRate, TransceiverSpeed, IsotpChannel, Padding, IsotpSocket, ServiceResult, Result, StreamHandler, SessionTokenHandler

# Configure logging
log_file_path = "responses_log.txt"
sfd2_log_file_path = "sfd2_log.txt"
logging.basicConfig(level=logging.INFO)

# Initialize SFD2 Factory Part Numbers List
sfd2_factory_parts = ["3Q0907530BB", "1EE937012D", "1EE937012B", "4KL907468Q", "5QS907530D"]

# Function to log data to a file
def log_response(data, filepath=log_file_path):
    with open(filepath, "a") as log_file:
        log_file.write(f"{data}\n\n")

# Function to save updated SFD2 parts list
def save_sfd2_factory_parts():
    with open("sfd2_parts.txt", "w") as file:
        for part in sfd2_factory_parts:
            file.write(part + "\n")

# Function to retrieve SFD2 parts from file on startup
def load_sfd2_factory_parts():
    global sfd2_factory_parts
    try:
        with open("sfd2_parts.txt", "r") as file:
            sfd2_factory_parts = [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        save_sfd2_factory_parts()  # Save the default parts list if file doesn't exist

# Function to initialize an OBD session
def initialize_obd_session(ticket_id):
    try:
        os.environ["OPENOBD_PARTNER_CLIENT_ID"] = st.secrets["api_keys"]["OPENOBD_PARTNER_CLIENT_ID"]
        os.environ["OPENOBD_PARTNER_CLIENT_SECRET"] = st.secrets["api_keys"]["OPENOBD_PARTNER_CLIENT_SECRET"]
        os.environ["OPENOBD_PARTNER_API_KEY"] = st.secrets["api_keys"]["OPENOBD_PARTNER_API_KEY"]
        os.environ["OPENOBD_CLUSTER_ID"] = st.secrets["api_keys"]["OPENOBD_CLUSTER_ID"]
        os.environ["OPENOBD_GRPC_HOST"] = st.secrets["api_keys"]["OPENOBD_GRPC_HOST"]

        openobd = OpenOBD()
        session = openobd.start_session_on_ticket(ticket_id)
        SessionTokenHandler(session)
        return session
    except AssertionError as e:
        st.error("Invalid Ticket ID or missing credentials. Please check the ID and try again.")
        logging.error(f"Failed to start session: {e}")
        return None
    except Exception as e:
        st.error("An unexpected error occurred. Please try again later.")
        logging.error(f"Unexpected error in starting session: {e}")
        return None

# Function to configure buses
def configure_buses(session):
    bus_configs = [
        BusConfiguration(
            bus_name="bus_6_14",
            can_bus=CanBus(
                pin_plus=6,
                pin_min=14,
                can_protocol=CanProtocol.CAN_PROTOCOL_ISOTP,
                can_bit_rate=CanBitRate.CAN_BIT_RATE_500,
                transceiver=TransceiverSpeed.TRANSCEIVER_SPEED_HIGH)),
        BusConfiguration(
            bus_name="bus_3_11",
            can_bus=CanBus(
                pin_plus=3,
                pin_min=11,
                can_protocol=CanProtocol.CAN_PROTOCOL_ISOTP,
                can_bit_rate=CanBitRate.CAN_BIT_RATE_500,
                transceiver=TransceiverSpeed.TRANSCEIVER_SPEED_HIGH))
    ]
    stream = StreamHandler(session.configure_bus)
    stream.send_and_close(bus_configs)

# Function to process each request and check for SFD2
def process_request(gtw, name, command):
    try:
        response = gtw.request(command, tries=2, timeout=5)
        if response:
            response_hex = response[6:]
            try:
                data = bytes.fromhex(response_hex).decode("utf-8").strip()
                result_str = f"{name}: {data}"
                log_response(result_str)

                sfd2_keywords = ["UNECE", "UN-ECE", "ECE"]

                # Check if the data matches any SFD2 criteria
                if (name == "ECU Type" and any(keyword in data for keyword in sfd2_keywords)) or \
                   (name == "Factory Part Number" and data in sfd2_factory_parts):
                    logging.info(f"SFD2 Detected: {data}")
                    return data, True  # SFD2 detected
                else:
                    logging.info(f"Not SFD2: {data}")
                    return data, False  # Not SFD2
            except UnicodeDecodeError:
                log_response(f"{name}: (Cannot decode to UTF-8) {response_hex}")
    except Exception as e:
        logging.error(f"Request failed: {e}")
        log_response(f"Request failed: {e}")

    return "Request failed", False

# Main function to run the OBD script and check for SFD2
def run_obd_script(ticket_id):
    responses = []
    sfd2_detected = False
    factory_part_number = None

    session = initialize_obd_session(ticket_id)
    if not session:
        responses.append("<span style='color: red;'>Failed to initialize session. Please check your Ticket ID.</span>")
        return responses, sfd2_detected, factory_part_number

    configure_buses(session)

    gtw_channel = IsotpChannel(bus_name="bus_6_14",
                               request_id=0x710,
                               response_id=0x77A,
                               padding=Padding.PADDING_ENABLED)
    gtw = IsotpSocket(session, gtw_channel)

    try:
        responses.append(f"Response: {gtw.request('1003', silent=True)}")
        log_response(f"Response: {responses[-1]}")

        requests = {
            "VIN": "22F190",
            "Factory Part Number": "22F187",
            "ECU Type": "22F19E",
        }
        for name, command in requests.items():
            data, is_sfd2 = process_request(gtw, name, command)
            responses.append(f"{name}: {data}")

            if name == "Factory Part Number":
                factory_part_number = data  # Save the Factory Part Number

            if is_sfd2:
                sfd2_detected = True

    finally:
        gtw.stop_stream()

    session.finish(ServiceResult(result=[Result.RESULT_SUCCESS]))

    if sfd2_detected:
        responses.append("<span style='color: red;'>The vehicle has SFD2</span>")
    else:
        responses.append("<span style='color: green;'>The vehicle has no SFD2</span>")

    return responses, sfd2_detected, factory_part_number

# Streamlit Interface
st.title("Check Vehicle Gateway SFD Status")

# Load SFD2 factory parts on startup
load_sfd2_factory_parts()

ticket_id = st.text_input("Enter Ticket ID:")

if st.button("Run Script"):
    if not ticket_id.isdigit():
        st.error("Ticket ID must contain only numbers. Please enter a valid numeric Ticket ID.")
    elif ticket_id:
        responses, sfd2_detected, factory_part_number = run_obd_script(ticket_id)
        st.write("### Results:")
        for response in responses:
            st.markdown(response, unsafe_allow_html=True)

        if not sfd2_detected and factory_part_number:
            st.warning("Are you sure the vehicle has no SFD2?")
            if st.button("Yes"):
                st.success("The vehicle has no SFD2.")
            if st.button("No"):
                st.warning("The factory part number will be added to the SFD2 list.")
                if st.button("Continue"):
                    sfd2_factory_parts.append(factory_part_number)
                    save_sfd2_factory_parts()
                    st.success(f"Factory part number {factory_part_number} has been successfully added to the SFD2 list.")
    else:
        st.error("Please enter a valid Ticket ID")

if st.button("Show SFD2 Fact_number"):
    st.write("### SFD2 Factory Part Numbers:")
    for part_number in sfd2_factory_parts:
        st.write(part_number)
