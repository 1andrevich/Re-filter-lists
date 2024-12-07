# Load the content of the newly uploaded file
final_file_path = 'sum/output/ipsum.lst'

# Read the content of the new file
with open(final_file_path, 'r') as file:
    final_lines = file.readlines()

# Create a new list for the formatted output
final_formatted_routes = [f"route {line.strip()} reject;" for line in final_lines]

# Output the formatted routes to a new file with the same name as requested
final_output_file_path = 'sum/output/formatted_routes.lst'
with open(final_output_file_path, 'w') as output_file:
    output_file.write('\n'.join(final_formatted_routes))

# Provide the path for the new file
final_output_file_path
