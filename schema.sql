CREATE DATABASE IF NOT EXISTS flutter_login_db;
USE flutter_login_db;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(150) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  role ENUM('teacher', 'admin') NOT NULL DEFAULT 'teacher',
  group_id INT NULL,
  password_setup_required BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS workshops (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(150) NOT NULL UNIQUE,
  capacity INT UNSIGNED NOT NULL DEFAULT 0,
  address VARCHAR(255) NOT NULL DEFAULT '',
  room VARCHAR(150) NOT NULL DEFAULT '',
  start_time VARCHAR(5) NOT NULL DEFAULT '',
  end_time VARCHAR(5) NOT NULL DEFAULT '',
  day_times TEXT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS workshop_teachers (
  workshop_id INT NOT NULL,
  user_id INT NOT NULL,
  PRIMARY KEY (workshop_id, user_id),
  CONSTRAINT fk_workshop_teacher_workshop FOREIGN KEY (workshop_id)
    REFERENCES workshops(id)
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  CONSTRAINT fk_workshop_teacher_user FOREIGN KEY (user_id)
    REFERENCES users(id)
    ON DELETE CASCADE
    ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS workshop_groups (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL UNIQUE,
  member_count INT UNSIGNED NOT NULL DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS workshop_rotation_assignments (
  id INT AUTO_INCREMENT PRIMARY KEY,
  rotation_date DATE NOT NULL,
  group_id INT NOT NULL,
  workshop_id INT NOT NULL,
  UNIQUE KEY uq_workshop_rotation_group_date (rotation_date, group_id),
  CONSTRAINT fk_rotation_group FOREIGN KEY (group_id)
    REFERENCES workshop_groups(id)
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  CONSTRAINT fk_rotation_workshop FOREIGN KEY (workshop_id)
    REFERENCES workshops(id)
    ON DELETE CASCADE
    ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS activity_types (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(80) NOT NULL UNIQUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS speakers (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(150) NOT NULL,
  role VARCHAR(150) NULL,
  institution VARCHAR(150) NULL,
  bio TEXT NULL,
  photo_path VARCHAR(255) NULL,
  cv_file_name VARCHAR(255) NULL,
  cv_file_path VARCHAR(255) NULL,
  cv_word_count INT UNSIGNED NOT NULL DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS activities (
  id INT AUTO_INCREMENT PRIMARY KEY,
  activity TEXT NOT NULL,
  title VARCHAR(200) NOT NULL,
  description TEXT NULL,
  date DATE NOT NULL,
  time TIME NOT NULL DEFAULT '00:00:00',
  time_end TIME NULL,
  responsible TEXT NULL,
  place TEXT NULL,
  modality VARCHAR(100) NOT NULL,
  activity_type_id INT NULL,
  file_name VARCHAR(255) NULL,
  file_path VARCHAR(255) NULL,
  file_data MEDIUMBLOB NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_activity_type FOREIGN KEY (activity_type_id)
    REFERENCES activity_types(id)
    ON DELETE SET NULL
    ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS activity_speakers (
  activity_id INT NOT NULL,
  speaker_id INT NOT NULL,
  PRIMARY KEY (activity_id, speaker_id),
  CONSTRAINT fk_activity_speaker_activity FOREIGN KEY (activity_id)
    REFERENCES activities(id)
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  CONSTRAINT fk_activity_speaker_speaker FOREIGN KEY (speaker_id)
    REFERENCES speakers(id)
    ON DELETE CASCADE
    ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO activity_types (name)
VALUES ('Taller'), ('Conferencia'), ('Seminario'), ('Curso'), ('Otro')
ON DUPLICATE KEY UPDATE name = VALUES(name);

CREATE TABLE IF NOT EXISTS attendance_records (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  kind ENUM('attendance', 'break') NOT NULL,
  event_date DATE NOT NULL,
  recorded_by INT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_attendance_user_kind_day (user_id, kind, event_date),
  CONSTRAINT fk_attendance_user FOREIGN KEY (user_id)
    REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS attendance_schedules (
  event_date DATE PRIMARY KEY,
  attendance_start TIME NOT NULL,
  attendance_end TIME NOT NULL,
  break_start TIME NOT NULL,
  break_end TIME NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS attendance_schedule_windows (
  id INT AUTO_INCREMENT PRIMARY KEY,
  event_date DATE NOT NULL,
  attendance_start TIME NOT NULL,
  attendance_end TIME NOT NULL,
  break_start TIME NOT NULL,
  break_end TIME NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_attendance_schedule_date (event_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
