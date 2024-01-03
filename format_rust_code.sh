#!/usr/bin/env bash

# Parse command line options
while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)
            mode="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check if mode is specified
if [ -z "$mode" ]; then
    echo "Please specify the mode using --mode option. Valid modes are 'check' and 'fix'."
    exit 1
fi

# Find all Markdown files in the current directory and its subdirectories
mapfile -t md_files < <(find . -type f -name "*.md")

count=0
# Iterate through each Markdown file
for file in "${md_files[@]}"; do
    # Use awk to extract Rust code blocks enclosed within triple backticks
    rust_code_blocks=$(awk '/```rust/{flag=1; next}/```/{flag=0} flag' "$file")

    # Count the number of Rust code blocks
    num_fences=$(awk '/```rust/{f=1} f{if(/```/){f=0; count++}} END{print count}' "$file")

    if [ -n "$rust_code_blocks" ]; then
        echo "Processing Rust code in $file"
        # Iterate through each Rust code block
        for ((i=1; i <= num_fences ; i++)); do
            # Extract individual Rust code block using awk
            current_rust_block=$(awk -v i="$i" '/```rust/{f=1; if (++count == i) next} f&&/```/{f=0;next} f' "$file")
            # Variable to check if we have added the main function
            add_main=0  
            # Check if the Rust code block is already inside a function
            if ! echo "$current_rust_block" | grep -q "fn main()"; then
                # If not, wrap it in a main function
                current_rust_block=$'fn main() {\n'"$current_rust_block"$'\n}'
                add_main=1
            fi
            if [ "$mode" == "check" ]; then
                # Apply changes to the Rust code block
                formatted_rust_code=$(echo "$current_rust_block" | rustfmt)
                # Use rustfmt to format the Rust code block, remove first and last lines, and remove the first 4 spaces if added  main function
                if [ "$add_main" == 1 ]; then
                    formatted_rust_code=$(echo "$formatted_rust_code" | sed '1d;$d' | sed 's/^    //')
                    current_rust_block=$(echo "$current_rust_block" | sed '1d;')
                    current_rust_block=$(echo "$current_rust_block" | sed '$d')
                fi
                if [ "$formatted_rust_code" == "$current_rust_block" ]; then
                    echo "No changes needed in Rust code block $i in $file"
                else
                    echo -e "\nChanges needed in Rust code block $i in $file:\n"
                    echo "$formatted_rust_code"
                    count=+1
                fi

            elif [ "$mode" == "fix" ]; then
                # Replace current_rust_block with formatted_rust_code in the file
                formatted_rust_code=$(echo "$current_rust_block" | rustfmt)
                # Use rustfmt to format the Rust code block, remove first and last lines, and remove the first 4 spaces if added  main function
                if [ "$add_main" == 1 ]; then
                    formatted_rust_code=$(echo "$formatted_rust_code" | sed '1d;$d' | sed 's/^    //')
                    current_rust_block=$(echo "$current_rust_block" | sed '1d;')
                    current_rust_block=$(echo "$current_rust_block" | sed '$d')
                fi
                # Check if the formatted code is the same as the current Rust code block
                if [ "$formatted_rust_code" == "$current_rust_block" ]; then
                    echo "No changes needed in Rust code block $i in $file"
                else
                    echo "Formatting Rust code block $i in $file"
                    # Replace current_rust_block with formatted_rust_code in the file
                    # Use awk to find the line number of the pattern

                    start_line=$(grep -n "^\`\`\`rust" "$file" | sed -n "${i}p" | cut -d: -f1)
                    end_line=$(grep -n "^\`\`\`" "$file" | awk -F: -v start_line="$start_line" '$1 > start_line {print $1; exit;}')

                    if [ -n "$start_line" ] && [ -n "$end_line" ]; then
                        # Print lines before the Rust code block
                        head -n "$((start_line - 1))" "$file"

                        # Print the formatted Rust code block
                        echo "\`\`\`rust"
                        echo "$formatted_rust_code"
                        echo "\`\`\`"

                        # Print lines after the Rust code block
                        tail -n +"$((end_line + 1))" "$file"
                    else
                        # Rust code block not found or end line not found
                        cat "$file"
                    fi > tmpfile && mv tmpfile "$file"

                fi
            else  
                echo "Unknown mode: $mode. Valid modes are 'check' and 'fix'."
                exit 1
            fi
        done
    fi
done

# CI failure if changes are needed
if [ $count -gt 0 ]; then
    echo "CI failed: Changes needed in Rust code blocks."
    exit 1
fi
