DROP TABLE IF EXISTS `isu_association_config`;

DROP TABLE IF EXISTS `isu_condition`;

DROP TABLE IF EXISTS `isu`;

DROP TABLE IF EXISTS `user`;

CREATE TABLE `isu` (
  `id` bigint AUTO_INCREMENT,
  `jia_isu_uuid` CHAR(36) NOT NULL UNIQUE,
  `name` VARCHAR(255) NOT NULL,
  `image` LONGBLOB,
  `character` VARCHAR(20) NOT NULL DEFAULT "",
  `jia_user_id` VARCHAR(30) NOT NULL,
  `created_at` DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
  `updated_at` DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY(`id`),
  INDEX jia_user_id_idx (`jia_user_id`),
  INDEX jia_isu_uuid_jia_user_id_idx (`jia_isu_uuid`, `jia_user_id`),
  INDEX character_idx (`character`)
) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8mb4;

CREATE TABLE `isu_condition` (
  `id` bigint DEFAULT 0,
  `jia_isu_uuid` CHAR(36) NOT NULL,
  `timestamp` DATETIME NOT NULL,
  `is_sitting` TINYINT(1) NOT NULL,
  `condition` VARCHAR(100) NOT NULL,
  `message` VARCHAR(100) NOT NULL,
  `created_at` DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY(`jia_isu_uuid`, `timestamp`)
) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8mb4;

CREATE TABLE `user` (
  `jia_user_id` VARCHAR(30) PRIMARY KEY,
  `created_at` DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8mb4;

CREATE TABLE `isu_association_config` (
  `name` VARCHAR(255) PRIMARY KEY,
  `url` VARCHAR(255) NOT NULL UNIQUE
) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8mb4;
