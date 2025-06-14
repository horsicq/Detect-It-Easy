import os
import sys

def count_signatures(base_path='../db'):
    # Verify base path exists
    if not os.path.exists(base_path):
        print(f"Error: Base path '{base_path}' does not exist.")
        return
    
    # Dictionary to hold subfolder and signature count
    signature_count = {}
    
    # Walk through each directory and count .sg files
    for root, dirs, files in os.walk(base_path):
        # Get relative subfolder path
        relative_path = os.path.relpath(root, base_path)
        
        # Skip the root path itself
        if relative_path == "." or ".vscode" in relative_path:
            continue
        
        # Count .sg files in the current directory
        count = sum(1 for file in files if file.endswith('.sg'))
        signature_count[relative_path] = count
    
    # Generate Markdown table
    for subfolder, count in signature_count.items():
        print(f"{subfolder} : {count}")

if __name__ == "__main__":
    # Get base path from command-line argument or use default
    base_path = sys.argv[1] if len(sys.argv) > 1 else '../db'
    count_signatures(base_path)
