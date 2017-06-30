# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require 'json'
require 'set'
require 'ipaddr'
require 'interval_tree'
require 'digest'

# The Access Watch filter adds information about robots visiting
# your website based on data from our robots database.
#
# The following fields might be created:
# [identity][type]      "robot"   If the visitor is a robot.
# [reputation][status]  string    The reputation of the visitor (see below).
# [robot][id]           number    A unique robot identifier
# [robot][name]         string    A robot's name to display to the user.
# [robot][url]          string    A link to the robot's page on the Access Watch database.
#
# Access Watch defines the following reputation statuses:
#
# nice	        perfect, as far as we know you can trust this entity
# ok	          all right, so far no reason to worry about this entity
# suspicious	  warning, nothing really bad, but the entity is on our radar
# bad           danger, there is good reasons to watch or block this entity
#
# This filter requires the Access Watch `robots.json` file to run.
# TBD: Instructions to download it.
#
class LogStash::Filters::Accesswatch < LogStash::Filters::Base

  config_name "accesswatch"

  # The path to the Access Watch database file.
  #
  # If not specified, this will default to './robots.json'.
  #
  config :db_path, :validate => :path, :default => "./robots.json"

  # The field containing the IP address.
  config :ip_source, :validate => :string, :required => true

  # The field containing the User-Agent string.
  config :ua_source, :validate => :string, :required => true

  private
  def build_indices(filename)
    file = File.read(filename)
    data = JSON.parse(file)
    # transform the CIDRs into Ruby ranges
    data['robots'].each {|robot|
      robot['cidrs'] = robot['cidrs'].collect {|cidr| cidr2range(cidr)}
    }
    # build indices
    @ip2robots = group_by_multi(data['robots'], 'ips')
    @cidr2robots = group_by_multi(data['robots'], 'cidrs')
    @ip2cidrs = IntervalTree::Tree.new(@cidr2robots.keys)
    @ua2robots = group_by_multi(data['robots'], 'uas')
    # compile and sort robot regexps
    data['regexps'].each { |regexp|
      regexp['pattern'] = Regexp.new(regexp['value'], Regexp::IGNORECASE)
    }
    @regexps = data['regexps'].sort {|a, b|
      a['priority'] <=> b['priority']
    }
  end

  public
  def register
    build_indices(@db_path)
  end

  # Transform a CIDR described as a 2-array [start size]
  # into a Ruby 3-dotted range.
  private
  def cidr2range(cidr)
    first = cidr[0]
    last = first + cidr[1]
    (first...last)
  end

  # Group elements of a collection by each value of a multi-valued attribute
  private
  def group_by_multi(coll, key)
    res = Hash.new {|hash, key| hash[key] = Array.new}
    coll.each {|el| el[key].each {|val| res[val].push(el)}}
    return res
  end

  # Take a User-Agent string and an IP address and return a hash with detected values
  private
  def detect(ua, ip)
    # Is it a robot based on the User-Agent?
    is_robot = false
    if ua.nil?
      # It is a robot if there is no User-Agent string
      is_robot = true
    else
      # Match against the regexps of known robots
      matches = @regexps.select { |regexp|
        regexp['pattern'].match(ua)
      }
      is_robot = !matches.empty?
    end
    # Look for robots with the same IP address
    ip_candidates = []
    if ip
      i = ip.ipv4? ? ip.ipv4_mapped.to_i : ip.to_i # convert IP to arbitrary length integer
      ip_candidates = @ip2robots[i]
    end
    # Look for robots on the same network if the UA already gave a clue it was a robot
    cidr_candidates = []
    if ip and is_robot
      cidrs = @ip2cidrs.search(i)
      cidr_candidates = cidrs.collect {|cidr| @cidr2robots[cidr]}.reduce([], :concat)
    end
    # Look for robots with the same User-Agent
    ua_candidates = []
    if ua
      ua_candidates = @ua2robots[Digest::MD5.hexdigest(ua)]
    end
    # Make a final decision
    robots = ((ip_candidates | cidr_candidates) & ua_candidates)
    if robots.empty?
      if is_robot
        {'identity' => {'type' => 'robot'}}
      end
    else
      robot = robots[0]
      url = "https://access.watch/database/robots/#{robot['reputation']}/#{robot['urlid'] or robot['id']}"
      {'identity'   => {'type' => 'robot'},
       'robot'      => {'id'   => robot['id'],
                        'name' => robot['name'],
                        'url'  => url},
       'reputation' => {'status' => robot['reputation']}}
    end
  end

  public
  def filter(event)
    ip_s = event.get(@ip_source)
    ip = IPAddr.new ip_s unless ip_s.nil?
    data = detect(event.get(@ua_source), ip)
    if data
      event.set('identity',   data['identity'])   unless data['identity'].nil?
      event.set('robot',      data['robot'])      unless data['robot'].nil?
      event.set('reputation', data['reputation']) unless data['reputation'].nil?
    end
    filter_matched(event)
  end

end
