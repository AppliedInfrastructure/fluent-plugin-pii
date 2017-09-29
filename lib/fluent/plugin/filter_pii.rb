require 'digest'
require 'ipaddr'
require 'base64'
require 'json'

module Fluent
  class PiiFilter < Filter
    Fluent::Plugin.register_filter( 'pii', self )

    config_param :rules, :array

    def configure( conf )
      super
    end

    def filter_stream( tag, es )
      new_stream = MultiEventStream.new

      # Compile like regexes by type and filter
      filters = {}
      @rules.each do |rule|
        next if filters.has_key?( rule['type']+rule['filter'] )
        filters[ rule['type']+rule['filter'] ] = [ 
          rule['type'],
          rule['filter'],
          Regexp.union( 
            @rules.select{ |s|
              s['filter'] == rule['filter'] and
              s['type'] == rule['type']
            }.map{ |m|
              Regexp.new( 
                m['regex']
              )
            }.compact
          )
        ]
      end

      es.each { |time, record|
        filtered_record = record.clone
        begin
          # Scan for patterns and generate filtered version
          captures = []
          filters.each do |key,filter|
            captures.push( [ 
              filter[2],
              Hash[
                filtered_record['message'].scan(
                  filter[2]
                ).map{ |x|
                  [ x,
                    SelectFilter.filter(
                      x,
                      filter[0]
                    ).send(
                      filter[1]
                    )
                  ]
                }
              ]
            ] )
          end

          # Replace patterns per configuration
          captures.each do |pattern,capture|
            capture.each do |pre,post|
              filtered_record['message'] = filtered_record['message'].gsub( pre, post )
            end
          end
          new_stream.add( time, filtered_record ) if filtered_record
        rescue => e
          router.emit_error_event( tag, time, record, e )
        end
      }
      new_stream
    end
  end

  class IPFilter < IPAddr
    def redact
      label = '[REDACTED_IP]:'
      if !self.is_private?
        return label+self.mask(0).to_s.force_encoding( Encoding::UTF_8 )
      else
        return self.to_s
      end
    end
    def hash
      label = '[ANONYMIZED_IP]:'
      if !self.is_private?
        ip_addr = Base64::strict_encode64( Digest::SHA256.digest( self.to_s ) )
        return label+ip_addr.force_encoding( Encoding::UTF_8 )
      else
        return self.to_s
      end
    end
    def obscure
      label = '[MASKED_IP]:'
      if !self.is_private?
        return label+self.mask(24).to_s.force_encoding( Encoding::UTF_8) 
      else
        return self.to_s
      end
    end
    def is_private?
      if self.ipv4?
        return true if IPAddr.new( "192.168.0.0/16" ).include?( self ) or
          IPAddr.new( "172.16.0.0/12" ).include?( self ) or
          IPAddr.new( "10.0.0.0/8" ).include?( self ) # Private
        return true if IPAddr.new( "169.254.0.0/16" ).include?( self ) # Link-Local
        return true if IPAddr.new( "100.64.0.0/10" ).include?( self ) # CG Nat
        return true if IPAddr.new( "127.0.0.0/8" ).include?( self ) # Loopback
        return true if IPAddr.new( "224.0.0.0/4" ).include?( self ) # Multicast
        return true if IPAddr.new( "240.0.0.0/4" ).include?( self ) # Future
      else
        return false
      end
    end
  end

  class StringFilter < String
    def redact
      label = '[REDACTED_STRING]:'
      size = self.length
      return label+'********'
    end
    def hash
      label = '[ANONYMIZED_STRING]:'
      string = Base64::strict_encode64( Digest::SHA256.digest( self ) )
      return label+string.force_encoding( Encoding::UTF_8 )
    end
    def obscure
      label = '[MASKED_STRING]:'
      size = self.length
      return label+( '*' * size )
    end
  end

  class EMailFilter
    def initialize( data )
      @data = data
    end
    def redact
      label = '{REDACTED_EMAIL]:'
      parts = @data.split( '@' )
      return label+( '*' * parts[0].length )+'@'+( '*' * parts[1].length )
    end
    def hash
      label = '[ANONYMIZED_EMAIL]:'
      email = Base64::strict_encode64( Digest::SHA256.digest( @data ) )
      return label+email.force_encoding( Encoding::UTF_8 )
    end
    def obscure
      label = '[MASKED_EMAIL]:'
      parts = @data.split( '@ ')
      return label+( '*' * parts[0].length )+'@'+parts[1]
    end
  end

  class SelectFilter
    def initialize( data, type )
      @data = data
      @type = type
    end
    def self.filter( data, type )
      case type
      when 'ip'
        IPFilter.new( data )
      when 'string'
        StringFilter.new( data )
      when 'email'
        EMailFilter.new( data )
      else
        raise "Unsupported type: #{type}"
      end
    end
  end
end
