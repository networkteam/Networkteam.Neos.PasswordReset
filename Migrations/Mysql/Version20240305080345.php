<?php

declare(strict_types=1);

namespace Neos\Flow\Persistence\Doctrine\Migrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Auto-generated Migration: Please modify to your needs!
 */
final class Version20240305080345 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Migrate passwordresettoken database to cascade remove operations on account removal';
    }

    public function up(Schema $schema): void
    {
        // this up() migration is auto-generated, please modify it to your needs
        $this->abortIf(
            !$this->connection->getDatabasePlatform() instanceof \Doctrine\DBAL\Platforms\MySQL80Platform,
            "Migration can only be executed safely on '\Doctrine\DBAL\Platforms\MySQL80Platform'."
        );

        $this->addSql('ALTER TABLE passwordresettoken DROP FOREIGN KEY FK_235DE1C77D3656A4');
        $this->addSql('ALTER TABLE passwordresettoken ADD CONSTRAINT FK_235DE1C77D3656A4 FOREIGN KEY (account) REFERENCES neos_flow_security_account (persistence_object_identifier) ON DELETE CASCADE');
    }

    public function down(Schema $schema): void
    {
        // this down() migration is auto-generated, please modify it to your needs
        $this->abortIf(
            !$this->connection->getDatabasePlatform() instanceof \Doctrine\DBAL\Platforms\MySQL80Platform,
            "Migration can only be executed safely on '\Doctrine\DBAL\Platforms\MySQL80Platform'."
        );

        $this->addSql('ALTER TABLE passwordresettoken DROP FOREIGN KEY FK_235DE1C77D3656A4');
        $this->addSql('ALTER TABLE passwordresettoken ADD CONSTRAINT FK_235DE1C77D3656A4 FOREIGN KEY (account) REFERENCES neos_flow_security_account (persistence_object_identifier) ON UPDATE NO ACTION ON DELETE CASCADE');
    }
}
