#!/usr/bin/env python3
import subprocess
import json
import os
import datetime
from pathlib import Path

# Configuration
STATS_FILE = "commit_statistics.json"
DEFAULT_HOURLY_RATE = 150  # Agency hourly rate in dollars

def get_commit_info(commit_hash="HEAD"):
    """Get basic information about a commit"""
    cmd = ["git", "show", "-s", "--format=%h|%an|%ae|%at|%s", commit_hash]
    output = subprocess.check_output(cmd).decode("utf-8").strip()
    hash_short, author, email, timestamp, subject = output.split("|")
    return {
        "hash": hash_short,
        "author": author,
        "email": email, 
        "timestamp": int(timestamp),
        "subject": subject,
        "date": datetime.datetime.fromtimestamp(int(timestamp)).strftime("%Y-%m-%d %H:%M:%S")
    }

def get_commit_stats(commit_hash="HEAD"):
    """Get statistics about the changes in a commit"""
    cmd = ["git", "diff", "--shortstat", f"{commit_hash}~1", commit_hash]
    try:
        output = subprocess.check_output(cmd).decode("utf-8").strip()
        files_changed = 0
        insertions = 0
        deletions = 0
        
        if output:
            parts = output.split(", ")
            for part in parts:
                if "file" in part:
                    files_changed = int(part.split(" ")[0])
                elif "insertion" in part:
                    insertions = int(part.split(" ")[0])
                elif "deletion" in part:
                    deletions = int(part.split(" ")[0])
        
        return {
            "files_changed": files_changed,
            "insertions": insertions,
            "deletions": deletions
        }
    except subprocess.CalledProcessError:
        # This might be the first commit
        return {
            "files_changed": 0,
            "insertions": 0,
            "deletions": 0
        }

def load_existing_stats():
    """Load existing statistics from the JSON file"""
    if os.path.exists(STATS_FILE):
        with open(STATS_FILE, "r") as f:
            return json.load(f)
    return {"commits": []}

def save_stats(stats):
    """Save statistics to the JSON file"""
    with open(STATS_FILE, "w") as f:
        json.dump(stats, f, indent=2)

def log_commit_statistics(commit_hash="HEAD", hours_spent=None, hourly_rate=DEFAULT_HOURLY_RATE):
    """Log statistics for a commit"""
    # Get existing stats
    all_stats = load_existing_stats()
    
    # Check if this commit is already logged
    for commit in all_stats["commits"]:
        if commit.get("hash") == commit_hash:
            print(f"Commit {commit_hash} already logged. Use --update to update it.")
            return
    
    # Get commit info
    commit_info = get_commit_info(commit_hash)
    commit_stats = get_commit_stats(commit_hash)
    
    # Ask for time spent if not provided
    if hours_spent is None:
        hours_spent = float(input(f"Hours spent on commit '{commit_info['subject']}': "))
    
    # Calculate cost
    cost = hours_spent * hourly_rate
    
    # Create entry
    entry = {
        **commit_info,
        **commit_stats,
        "hours_spent": hours_spent,
        "hourly_rate": hourly_rate,
        "cost": cost,
        "log_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Add to stats
    all_stats["commits"].append(entry)
    
    # Calculate project totals
    total_hours = sum(commit["hours_spent"] for commit in all_stats["commits"])
    total_cost = sum(commit["cost"] for commit in all_stats["commits"])
    all_stats["project_totals"] = {
        "total_hours": total_hours,
        "total_cost": total_cost,
        "last_updated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Save stats
    save_stats(all_stats)
    
    print(f"Logged statistics for commit {commit_hash}:")
    print(f"  Subject: {commit_info['subject']}")
    print(f"  Hours spent: {hours_spent}")
    print(f"  Cost: ${cost:.2f}")
    print(f"  Project totals: {total_hours} hours, ${total_cost:.2f}")

def generate_report():
    """Generate a summary report of all commits"""
    all_stats = load_existing_stats()
    
    if not all_stats["commits"]:
        print("No commit statistics found.")
        return
    
    print("\n==== Commit Statistics Report ====\n")
    print("Individual Commits:")
    print("-" * 80)
    
    for commit in sorted(all_stats["commits"], key=lambda x: x["timestamp"]):
        print(f"Commit: {commit['hash']} - {commit['date']}")
        print(f"Subject: {commit['subject']}")
        print(f"Author: {commit['author']} <{commit['email']}>")
        print(f"Changes: {commit['files_changed']} files, +{commit['insertions']}, -{commit['deletions']}")
        print(f"Time: {commit['hours_spent']:.2f} hours")
        print(f"Cost: ${commit['cost']:.2f}")
        print("-" * 80)
    
    if "project_totals" in all_stats:
        totals = all_stats["project_totals"]
        print("\nProject Totals:")
        print(f"Total Hours: {totals['total_hours']:.2f}")
        print(f"Total Cost: ${totals['total_cost']:.2f}")
        print(f"Last Updated: {totals['last_updated']}")
    
    print("\n==== End of Report ====\n")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Log statistics for git commits")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Log command
    log_parser = subparsers.add_parser("log", help="Log statistics for a commit")
    log_parser.add_argument("--commit", "-c", default="HEAD", help="Commit hash (default: HEAD)")
    log_parser.add_argument("--hours", "-t", type=float, help="Hours spent on the commit")
    log_parser.add_argument("--rate", "-r", type=float, default=DEFAULT_HOURLY_RATE, help="Hourly rate")
    
    # Report command
    report_parser = subparsers.add_parser("report", help="Generate a report of commit statistics")
    
    args = parser.parse_args()
    
    if args.command == "log":
        log_commit_statistics(args.commit, args.hours, args.rate)
    elif args.command == "report":
        generate_report()
    else:
        parser.print_help()

if __name__ == "__main__":
    main() 