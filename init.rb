require 'ardes/authenticated_system/table_definition'

ActiveRecord::ConnectionAdapters::TableDefinition.send :include, Ardes::AuthenticatedSystem::TableDefinition