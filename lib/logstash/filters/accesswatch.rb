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
    coll.each {|el|
      if !el[key].nil?
        el[key].each {|val|
          res[val].push(el)
        }
      end
    }
    return res
  end

  private
  def build_indices(filename)
    file = File.read(filename)
    robots = JSON.parse(file)
    robots.each {|robot|
      if !robot['cidrs'].nil?
        robot['cidrs'] = robot['cidrs'].collect {|cidr| cidr2range(cidr)}
      end
    }
    @ip2robots = group_by_multi(robots, 'ips')
    @cidr2robots = group_by_multi(robots, 'cidrs')
    @ip2cidrs = IntervalTree::Tree.new(@cidr2robots.keys)
    @ua2robots = group_by_multi(robots, 'uas')
  end

  public
  def register
    build_indices(@db_path)
  end

  # Take a User-Agent string and an IP address and return a robot description, or nil.
  private
  def detect(ua, ip)
    # Look for robots with the same IP addressor CIDR
    ip_candidates = []
    cidr_candidates = []
    if ip
      i = ip.ipv4? ? ip.ipv4_mapped.to_i : ip.to_i # convert IP to arbitrary length integer
      ip_candidates = @ip2robots[i]
      cidrs = @ip2cidrs.search(i)
      cidr_candidates = cidrs.collect {|cidr| @cidr2robots[cidr]}.reduce([], :concat) unless cidrs.nil?
    end
    # Look for robots with the same User-Agent
    ua_candidates = []
    if ua
      ua_candidates = @ua2robots[Digest::MD5.hexdigest(ua)]
    end
    # Make a final decision
    robots = ((ip_candidates | cidr_candidates) & ua_candidates)
    if !robots.empty?
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
    robot = detect(event.get(@ua_source), ip)
    if robot
      event.set('identity',   robot['identity'])   unless robot['identity'].nil?
      event.set('robot',      robot['robot'])      unless robot['robot'].nil?
      event.set('reputation', robot['reputation']) unless robot['reputation'].nil?
    end
    filter_matched(event)
  end

end
